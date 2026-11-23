//! Signing with FIDO security keys, for the key files of OpenSSH's
//! `ecdsa-sk` and `ed25519-sk` keys: the file holds a handle to a
//! credential on the security key, and only the key can sign with it.
//!
//! On Windows, the WebAuthn API asks the key, with Windows' own dialog for
//! the touch and the PIN (programs may not talk to FIDO devices directly
//! there). On Linux and macOS, DbCraft talks CTAP2 (or U2F) to the key over
//! USB HID itself, as libfido2 does for OpenSSH.

#[cfg(any(test, target_os = "linux", target_os = "macos"))]
mod cbor;
#[cfg(any(test, target_os = "linux", target_os = "macos"))]
mod ctap;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(test)]
pub(crate) mod soft;
#[cfg(windows)]
mod windows;

/// How long a security key may take to be touched.
pub(crate) const TOUCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// What to sign, with which credential.
pub(crate) struct Request<'a> {
    /// The FIDO relying party ID of the key, usually `ssh:`.
    pub application: &'a str,
    pub key_handle: &'a [u8],
    /// The data to sign. The key signs its SHA-256 hash (the "client data
    /// hash") after its authenticator data.
    pub message: &'a [u8],
    /// Whether the key is to be touched (the key file's flag 0x01; unset by
    /// `ssh-keygen -O no-touch-required`).
    pub user_presence: bool,
    /// Whether the key is to verify the user, by PIN or fingerprint (flag
    /// 0x04, `-O verify-required`).
    pub user_verification: bool,
    /// The key's PIN, where DbCraft asks the key itself (not on Windows).
    pub pin: Option<&'a str>,
}

/// A security key's signature.
#[derive(Debug)]
pub(crate) struct Assertion {
    /// The authenticator data's flags: 0x01 touched, 0x04 user verified.
    pub flags: u8,
    pub counter: u32,
    /// DER for ECDSA, 64 bytes for Ed25519.
    pub signature: Vec<u8>,
}

/// Asks the security key to sign, waiting for the touch. Blocks.
pub(crate) fn sign(request: &Request) -> Result<Assertion, String> {
    #[cfg(test)]
    if let Some(key) = soft::PLUGGED_IN.lock().expect("soft key mutex").take() {
        return hid_sign(vec![key], request);
    }
    #[cfg(windows)]
    {
        windows::sign(request)
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        #[cfg(target_os = "linux")]
        let devices = linux::devices()?;
        #[cfg(target_os = "macos")]
        let devices = macos::devices()?;
        hid_sign(devices, request)
    }
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        let _ = request;
        Err(
            "DbCraft can't use security keys on this system: add the key to the SSH agent \
             and leave the key file empty"
                .into(),
        )
    }
}

/// Signs with the one of `devices` that holds the credential.
#[cfg(any(test, target_os = "linux", target_os = "macos"))]
pub(crate) fn hid_sign<D: ctap::Device>(
    devices: Vec<D>,
    request: &Request,
) -> Result<Assertion, String> {
    let mut keys = Vec::new();
    for device in devices {
        match ctap::Authenticator::open(device) {
            Ok(key) => keys.push(key),
            Err(e) => tracing::warn!("opening a security key: {e}"),
        }
    }
    let mut key = match keys.len() {
        0 => return Err("no security key found: plug it in and connect again".into()),
        1 => keys.pop().expect("one key"),
        _ => keys
            .into_iter()
            .find_map(|mut key| match key.holds(request) {
                Ok(true) => Some(key),
                Ok(false) => None,
                Err(e) => {
                    tracing::warn!("asking a security key for the credential: {e}");
                    None
                }
            })
            .ok_or("none of the security keys plugged in holds this key")?,
    };
    tracing::info!("waiting for the security key's touch");
    key.sign(request)
        .map_err(|e| format!("the security key didn't sign: {e}"))
}

#[cfg(test)]
mod tests {
    use ring::signature::{ECDSA_P256_SHA256_ASN1, ED25519, UnparsedPublicKey};

    use super::soft::{Config, SoftKey};
    use super::*;

    const MESSAGE: &[u8] = b"the data of a login";

    /// Signs for `key`'s credential with `key` and `others` plugged in;
    /// checks the signature as the server does.
    fn sign_on(
        key: SoftKey,
        others: Vec<SoftKey>,
        verify: bool,
        pin: Option<&str>,
    ) -> Result<Assertion, String> {
        let (handle, public) = (key.key_handle.clone(), key.public_key());
        let ed25519 = matches!(key.credential, soft::Credential::Ed25519(_));
        let request = Request {
            application: "ssh:",
            key_handle: &handle,
            message: MESSAGE,
            user_presence: true,
            user_verification: verify,
            pin,
        };
        let mut devices = others;
        devices.push(key);
        let assertion = hid_sign(devices, &request)?;
        let mut signed = ctap::sha256(b"ssh:").to_vec();
        signed.push(assertion.flags);
        signed.extend(assertion.counter.to_be_bytes());
        signed.extend(ctap::sha256(MESSAGE));
        let alg: &dyn ring::signature::VerificationAlgorithm = if ed25519 {
            &ED25519
        } else {
            &ECDSA_P256_SHA256_ASN1
        };
        UnparsedPublicKey::new(alg, &public)
            .verify(&signed, &assertion.signature)
            .expect("the signature verifies");
        Ok(assertion)
    }

    fn sign(config: Config, verify: bool, pin: Option<&str>) -> Result<Assertion, String> {
        sign_on(SoftKey::new(false, config), Vec::new(), verify, pin)
    }

    fn with_pin() -> Config {
        Config {
            pin: Some("4711".into()),
            ..Config::default()
        }
    }

    #[test]
    fn ctap2_signs() {
        for ed25519 in [false, true] {
            let key = SoftKey::new(ed25519, Config::default());
            let log = key.log.clone();
            let assertion = sign_on(key, Vec::new(), false, None).unwrap();
            assert_eq!((assertion.flags, assertion.counter), (0x01, 42));
            assert_eq!(log.lock().unwrap().assertions, 1);
        }
    }

    #[test]
    fn u2f_signs() {
        let u2f = || Config {
            ctap2: false,
            ..Config::default()
        };
        assert_eq!(sign(u2f(), false, None).unwrap().flags, 0x01);
        let error = sign(u2f(), true, Some("4711")).unwrap_err();
        assert!(error.contains("verify the user"), "{error}");
    }

    #[test]
    fn pins() {
        for (protocols, token) in [(vec![1], false), (vec![1, 2], false), (vec![1, 2], true)] {
            let config = || Config {
                pin_protocols: protocols.clone(),
                pin_uv_auth_token: token,
                ..with_pin()
            };
            let assertion = sign(config(), true, Some("4711")).unwrap();
            assert_eq!(assertion.flags, 0x05, "{protocols:?}");
            let error = sign(config(), true, Some("0000")).unwrap_err();
            assert!(error.contains("PIN is wrong (7 tries left"), "{error}");
            let error = sign(config(), true, None).unwrap_err();
            assert!(error.contains("enter it as the SSH password"), "{error}");
        }
        // Too short to be a PIN: not even tried.
        let key = SoftKey::new(false, with_pin());
        let log = key.log.clone();
        let error = sign_on(key, Vec::new(), true, Some("47")).unwrap_err();
        assert!(error.contains("requirements"), "{error}");
        assert_eq!(log.lock().unwrap().pin_tries, 0);
        // A key that asks for its PIN even when the key file doesn't.
        let always = || Config {
            always_uv: true,
            ..with_pin()
        };
        assert_eq!(sign(always(), false, Some("4711")).unwrap().flags, 0x05);
        let error = sign(always(), false, None).unwrap_err();
        assert!(error.contains("needs its PIN"), "{error}");
        // Without a PIN set, there is no verifying by PIN.
        let error = sign(Config::default(), true, Some("4711")).unwrap_err();
        assert!(error.contains("no PIN set"), "{error}");
        // A fingerprint reader verifies by itself.
        let bio = Config {
            builtin_uv: true,
            ..Config::default()
        };
        assert_eq!(sign(bio, true, None).unwrap().flags, 0x05);
    }

    #[test]
    fn picks_the_key_that_holds_the_credential() {
        let other = SoftKey::new(false, Config::default());
        let u2f_other = SoftKey::new(
            false,
            Config {
                ctap2: false,
                ..Config::default()
            },
        );
        let key = SoftKey::new(false, Config::default());
        let (log, other_log) = (key.log.clone(), other.log.clone());
        sign_on(key, vec![other, u2f_other], false, None).unwrap();
        assert_eq!(log.lock().unwrap().assertions, 1);
        // Asked without a touch, not signed with.
        let other_log = other_log.lock().unwrap();
        assert_eq!((other_log.probes, other_log.assertions), (1, 0));
    }

    #[test]
    fn no_key_holds_the_credential() {
        let request = Request {
            application: "ssh:",
            key_handle: &[1; 64],
            message: MESSAGE,
            user_presence: true,
            user_verification: false,
            pin: None,
        };
        let soft = || SoftKey::new(false, Config::default());
        let error = hid_sign(vec![soft(), soft()], &request).unwrap_err();
        assert!(error.contains("none of the security keys"), "{error}");
        let error = hid_sign(vec![soft()], &request).unwrap_err();
        assert!(error.contains("doesn't hold this key"), "{error}");
        let error = hid_sign(Vec::<SoftKey>::new(), &request).unwrap_err();
        assert!(error.contains("no security key found"), "{error}");
    }
}
