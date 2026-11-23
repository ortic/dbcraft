//! Logging in with the key file of a security key (`ssh-keygen -t
//! ecdsa-sk` or `ed25519-sk`): the security key signs, and its signature
//! goes to the server in OpenSSH's format (PROTOCOL.u2f): the algorithm,
//! the signature, then the key's flags and counter.

use std::future::Future;
use std::path::Path;

use russh::keys::agent::AgentIdentity;
use russh::keys::{HashAlg, PrivateKey};

use crate::fido::{self, Assertion, Request};

const ECDSA: &str = "sk-ecdsa-sha2-nistp256@openssh.com";
const ED25519: &str = "sk-ssh-ed25519@openssh.com";
/// The key file's flags (`ssh-keygen -O`).
const USER_PRESENCE_REQUIRED: u8 = 0x01;
const USER_VERIFICATION_REQUIRED: u8 = 0x04;

/// Whether `path` is a security key's key file, encrypted or not.
pub(super) fn is_security_key(path: &Path) -> bool {
    PrivateKey::read_openssh_file(path).is_ok_and(|key| {
        let data = key.public_key().key_data();
        data.is_sk_ecdsa_p256() || data.is_sk_ed25519()
    })
}

/// Whether the key file at `path` is protected by a passphrase.
pub(super) fn is_encrypted(path: &Path) -> bool {
    PrivateKey::read_openssh_file(path).is_ok_and(|key| key.is_encrypted())
}

/// Signs the login with a security key.
#[derive(Clone)]
pub(super) struct SecurityKey {
    algorithm: &'static str,
    application: String,
    key_handle: Vec<u8>,
    flags: u8,
    /// The key's PIN, if the key asks for one (not on Windows: Windows asks
    /// itself).
    pin: Option<String>,
}

/// Why the security key didn't sign.
#[derive(Debug)]
pub(super) struct SignError(pub String);

impl From<russh::SendError> for SignError {
    fn from(_: russh::SendError) -> Self {
        Self("the SSH connection closed".into())
    }
}

impl SecurityKey {
    /// The security key of a (decrypted) key file, if it is one.
    pub fn new(key: &PrivateKey, pin: Option<String>) -> Option<Self> {
        let data = key.key_data();
        let (algorithm, application, key_handle, flags) = if let Some(sk) = data.sk_ecdsa_p256() {
            (
                ECDSA,
                sk.public().application(),
                sk.key_handle(),
                sk.flags(),
            )
        } else {
            let sk = data.sk_ed25519()?;
            (
                ED25519,
                sk.public().application(),
                sk.key_handle(),
                sk.flags(),
            )
        };
        Some(Self {
            algorithm,
            application: application.to_owned(),
            key_handle: key_handle.to_vec(),
            flags,
            pin: pin.filter(|pin| !pin.is_empty()),
        })
    }

    /// The SSH signature of `message`, with `sign` asking the key.
    fn signature(
        &self,
        message: &[u8],
        sign: impl FnOnce(&Request) -> Result<Assertion, String>,
    ) -> Result<Vec<u8>, String> {
        let request = Request {
            application: &self.application,
            key_handle: &self.key_handle,
            message,
            user_presence: self.flags & USER_PRESENCE_REQUIRED != 0,
            user_verification: self.flags & USER_VERIFICATION_REQUIRED != 0,
            pin: self.pin.as_deref(),
        };
        let assertion = sign(&request)?;
        let signature = if self.algorithm == ECDSA {
            ecdsa_signature(&assertion.signature)
                .ok_or("the security key's ECDSA signature is malformed")?
        } else if assertion.signature.len() == 64 {
            assertion.signature
        } else {
            return Err("the security key's Ed25519 signature is malformed".into());
        };
        let mut blob = string(self.algorithm.as_bytes());
        blob.extend(string(&signature));
        blob.push(assertion.flags);
        blob.extend(assertion.counter.to_be_bytes());
        Ok(blob)
    }
}

impl russh::Signer for SecurityKey {
    type Error = SignError;

    fn auth_sign(
        &mut self,
        _key: &AgentIdentity,
        _hash_alg: Option<HashAlg>,
        to_sign: Vec<u8>,
    ) -> impl Future<Output = Result<Vec<u8>, Self::Error>> + Send {
        let key = self.clone();
        async move {
            // The key blocks until it is touched; the tunnel's runtime has
            // other connections to carry meanwhile.
            tokio::task::spawn_blocking(move || {
                let blob = key.signature(&to_sign, fido::sign)?;
                // What russh sends is the data signed with the signature
                // after it, as from an agent.
                let mut data = to_sign;
                data.extend(string(&blob));
                Ok(data)
            })
            .await
            .map_err(|e| SignError(format!("the security key: {e}")))?
            .map_err(SignError)
        }
    }
}

/// An SSH string: its length, then its bytes.
fn string(bytes: &[u8]) -> Vec<u8> {
    let mut out = (bytes.len() as u32).to_be_bytes().to_vec();
    out.extend_from_slice(bytes);
    out
}

/// A DER ECDSA signature (`SEQUENCE { INTEGER r, INTEGER s }`) as SSH's:
/// r and s as mpints. DER integers are already what an mpint holds.
fn ecdsa_signature(der: &[u8]) -> Option<Vec<u8>> {
    fn tlv(data: &[u8], tag: u8) -> Option<(&[u8], &[u8])> {
        let (&t, rest) = data.split_first()?;
        let (&len, rest) = rest.split_first()?;
        let (len, rest) = match len {
            0..=0x7f => (usize::from(len), rest),
            0x81 => {
                let (&len, rest) = rest.split_first()?;
                (usize::from(len), rest)
            }
            _ => return None,
        };
        (t == tag && rest.len() >= len).then(|| rest.split_at(len))
    }
    let (sequence, rest) = tlv(der, 0x30)?;
    if !rest.is_empty() {
        return None;
    }
    let (r, rest) = tlv(sequence, 0x02)?;
    let (s, rest) = tlv(rest, 0x02)?;
    // Negative or empty integers aren't a signature.
    if !rest.is_empty()
        || [r, s]
            .iter()
            .any(|n| n.first().is_none_or(|b| b & 0x80 != 0))
    {
        return None;
    }
    Some([string(r), string(s)].concat())
}

#[cfg(test)]
mod tests {
    use russh::keys::PublicKey;
    use russh::keys::signature::Verifier;
    use russh::keys::ssh_encoding::Decode;
    use russh::keys::ssh_key::Signature;

    use super::*;
    use crate::fido::soft::{Config, SoftKey};

    /// The key file's public key for `soft`.
    fn public_key(soft: &SoftKey, ed25519: bool) -> PublicKey {
        let mut blob = Vec::new();
        if ed25519 {
            blob.extend(string(ED25519.as_bytes()));
        } else {
            blob.extend(string(ECDSA.as_bytes()));
            blob.extend(string(b"nistp256"));
        }
        blob.extend(string(&soft.public_key()));
        blob.extend(string(soft.application.as_bytes()));
        PublicKey::from_bytes(&blob).unwrap()
    }

    fn security_key(soft: &SoftKey, ed25519: bool, flags: u8) -> SecurityKey {
        SecurityKey {
            algorithm: if ed25519 { ED25519 } else { ECDSA },
            application: soft.application.clone(),
            key_handle: soft.key_handle.clone(),
            flags,
            pin: None,
        }
    }

    /// Signs as at a login, and checks the signature as sshd does.
    fn verify(ed25519: bool, flags: u8, config: Config) -> u8 {
        let soft = SoftKey::new(ed25519, config);
        let public = public_key(&soft, ed25519);
        let key = security_key(&soft, ed25519, flags);
        let message = b"session id and userauth request".to_vec();
        let blob = key
            .signature(&message, |request| {
                crate::fido::hid_sign(vec![soft], request)
            })
            .unwrap();
        let signature = Signature::decode(&mut &blob[..]).unwrap();
        Verifier::verify(&public, &message, &signature).unwrap();
        assert!(Verifier::verify(&public, b"another message", &signature).is_err());
        // The flags byte, before the counter.
        blob[blob.len() - 5]
    }

    #[test]
    fn signatures_verify() {
        assert_eq!(
            verify(false, USER_PRESENCE_REQUIRED, Config::default()),
            0x01
        );
        assert_eq!(
            verify(true, USER_PRESENCE_REQUIRED, Config::default()),
            0x01
        );
        // -O no-touch-required
        assert_eq!(verify(false, 0, Config::default()), 0x00);
        // A U2F key.
        let u2f = Config {
            ctap2: false,
            ..Config::default()
        };
        assert_eq!(verify(false, USER_PRESENCE_REQUIRED, u2f), 0x01);
        // -O verify-required, by fingerprint.
        let bio = Config {
            builtin_uv: true,
            ..Config::default()
        };
        assert_eq!(
            verify(
                false,
                USER_PRESENCE_REQUIRED | USER_VERIFICATION_REQUIRED,
                bio
            ),
            0x05
        );
    }

    #[test]
    fn ecdsa_from_der() {
        // r with its high bit set keeps the zero DER puts before it.
        let der = [
            0x30, 0x09, 0x02, 0x02, 0x00, 0x80, 0x02, 0x03, 0x01, 0x02, 0x03,
        ];
        assert_eq!(
            ecdsa_signature(&der).unwrap(),
            [0, 0, 0, 2, 0x00, 0x80, 0, 0, 0, 3, 1, 2, 3]
        );
        for bad in [
            &[][..],
            &[0x30, 0x03, 0x02, 0x01, 0x01],                   // no s
            &[0x30, 0x06, 0x02, 0x01, 0x81, 0x02, 0x01, 0x01], // negative r
            &[0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x00], // trailing
            &[0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01], // not a sequence
        ] {
            assert!(ecdsa_signature(bad).is_none(), "{bad:02x?}");
        }
    }

    const HOST_KEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACClEhoSIagwuB36qjpnnthtjKcuq3+bXd9hkstg8x23vQAAAIi5usgHubrI
BwAAAAtzc2gtZWQyNTUxOQAAACClEhoSIagwuB36qjpnnthtjKcuq3+bXd9hkstg8x23vQ
AAAEBNRdzTUJqyUfuM1ubN9qtwRxGXCiHQmKchWlpyrvnjLKUSGhIhqDC4HfqqOmee2G2M
py6rf5td32GSy2DzHbe9AAAABWhvc3Qx
-----END OPENSSH PRIVATE KEY-----
";

    /// Accepts `key` for the user `dbcraft`.
    struct Server {
        key: PublicKey,
    }

    impl russh::server::Handler for Server {
        type Error = russh::Error;

        // As sshd: only an authorized key is asked to sign.
        async fn auth_publickey_offered(
            &mut self,
            _user: &str,
            offer: russh::server::PublicKeyOffer<'_>,
        ) -> Result<russh::server::Auth, Self::Error> {
            Ok(if offer.public_key.key_data() == self.key.key_data() {
                russh::server::Auth::Accept
            } else {
                russh::server::Auth::reject()
            })
        }

        async fn auth_publickey(
            &mut self,
            user: &str,
            key: russh::server::VerifiedPublicKey<'_>,
        ) -> Result<russh::server::Auth, Self::Error> {
            Ok(
                if user == "dbcraft" && key.public_key.key_data() == self.key.key_data() {
                    russh::server::Auth::Accept
                } else {
                    russh::server::Auth::reject()
                },
            )
        }
    }

    /// Logs in to an SSH server that knows `authorized` with the key file
    /// of `soft`, plugged in.
    fn log_in(soft: SoftKey, authorized: PublicKey, flags: u8, name: &str) -> Result<(), String> {
        use russh::keys::ssh_key::private::{KeypairData, SkEcdsaSha2NistP256};

        let dir = std::env::temp_dir().join(format!("dbcraft-sk-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let public = public_key(&soft, false);
        let sk = SkEcdsaSha2NistP256::new(
            public.key_data().sk_ecdsa_p256().unwrap().clone(),
            flags,
            soft.key_handle.clone(),
        )
        .unwrap();
        let key_file = dir.join("id_ecdsa_sk");
        let private = PrivateKey::new(KeypairData::SkEcdsaSha2NistP256(sk), "sk").unwrap();
        std::fs::write(
            &key_file,
            private
                .to_openssh(russh::keys::ssh_key::LineEnding::LF)
                .unwrap(),
        )
        .unwrap();
        assert!(is_security_key(&key_file) && !is_encrypted(&key_file));

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let listener = runtime
            .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        let host_key = PrivateKey::from_openssh(HOST_KEY).unwrap();
        let known_hosts = dir.join("known_hosts");
        super::super::HostKey::new("127.0.0.1", port, host_key.public_key(), &known_hosts)
            .trust()
            .unwrap();
        let config = std::sync::Arc::new(russh::server::Config {
            keys: vec![host_key],
            methods: russh::MethodSet::from(&[russh::MethodKind::PublicKey][..]),
            auth_rejection_time: std::time::Duration::from_millis(10),
            auth_rejection_time_initial: Some(std::time::Duration::ZERO),
            ..Default::default()
        });
        runtime.spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let handler = Server { key: authorized };
            if let Ok(running) = russh::server::run_stream(config, stream, handler).await {
                let _ = running.await;
            }
        });

        *crate::fido::soft::PLUGGED_IN.lock().unwrap() = Some(soft);
        let params = super::super::SshParams {
            host: format!("127.0.0.1:{port}"),
            username: "dbcraft".into(),
            password: String::new(),
            key_file: Some(key_file),
            known_hosts,
        };
        let server = super::super::Server::parse(&params.host).unwrap();
        let result = runtime.block_on(super::super::login(&server, &params));
        crate::fido::soft::PLUGGED_IN.lock().unwrap().take();
        result.map(drop).map_err(|e| e.message)
    }

    /// The whole login, as sshd checks it: russh's server verifies the
    /// signature with the key file's public key.
    #[test]
    fn logs_in_with_a_security_key() {
        let soft = SoftKey::new(false, Config::default());
        let log = soft.log.clone();
        let public = public_key(&soft, false);
        log_in(soft, public, USER_PRESENCE_REQUIRED, "accepted").unwrap();
        assert_eq!(log.lock().unwrap().assertions, 1);

        // A server that doesn't know the key says so.
        let other = SoftKey::new(false, Config::default());
        let soft = SoftKey::new(false, Config::default());
        let log = soft.log.clone();
        let error = log_in(
            soft,
            public_key(&other, false),
            USER_PRESENCE_REQUIRED,
            "unknown",
        )
        .unwrap_err();
        assert!(
            error.contains("didn't accept the security key of"),
            "{error}"
        );
        // Asked first, as OpenSSH asks: the key isn't touched in vain.
        assert_eq!(log.lock().unwrap().assertions, 0);

        // The key needs its PIN, and there is none.
        let soft = SoftKey::new(
            false,
            Config {
                pin: Some("4711".into()),
                ..Config::default()
            },
        );
        let public = public_key(&soft, false);
        let error = log_in(
            soft,
            public,
            USER_PRESENCE_REQUIRED | USER_VERIFICATION_REQUIRED,
            "pin",
        )
        .unwrap_err();
        assert!(error.contains("needs its PIN"), "{error}");
    }
}
