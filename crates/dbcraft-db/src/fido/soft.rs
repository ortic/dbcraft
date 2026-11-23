//! A security key in software, for the tests: a HID device that answers
//! CTAPHID, CTAP2 (getInfo, getAssertion, clientPin with PIN protocols one
//! and two) and U2F's authenticate, with one credential.

use std::collections::VecDeque;
use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ring::agreement;
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{self, EcdsaKeyPair, Ed25519KeyPair, KeyPair};

use super::cbor::Value;
use super::ctap::{self, Device, PinProtocol, REPORT};

/// The key that [`super::sign`] signs with in tests, instead of the
/// platform's; taken by the first signature.
pub static PLUGGED_IN: Mutex<Option<SoftKey>> = Mutex::new(None);

pub enum Credential {
    Ecdsa(EcdsaKeyPair),
    Ed25519(Ed25519KeyPair),
}

pub struct Config {
    pub ctap2: bool,
    pub u2f: bool,
    pub pin: Option<String>,
    /// A fingerprint reader: `uv` without a PIN.
    pub builtin_uv: bool,
    /// Refuses getAssertion without the PIN, whatever is asked.
    pub always_uv: bool,
    pub pin_protocols: Vec<i64>,
    pub pin_uv_auth_token: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            ctap2: true,
            u2f: true,
            pin: None,
            builtin_uv: false,
            always_uv: false,
            pin_protocols: vec![1, 2],
            pin_uv_auth_token: true,
        }
    }
}

/// What the key saw, for the tests to check.
#[derive(Default, Debug)]
pub struct Log {
    pub assertions: usize,
    pub pin_tries: usize,
    pub probes: usize,
}

pub struct SoftKey {
    pub application: String,
    pub key_handle: Vec<u8>,
    pub credential: Credential,
    pub config: Config,
    pub log: Arc<Mutex<Log>>,
    counter: u32,
    retries: i64,
    cid: u32,
    /// The request being received: command, length, data.
    incoming: Option<(u32, u8, usize, Vec<u8>)>,
    outgoing: VecDeque<[u8; REPORT]>,
    key_agreement: Option<(u8, agreement::EphemeralPrivateKey)>,
    pin_token: Option<Vec<u8>>,
    /// U2F answers "touch me" once before it signs.
    u2f_touched: bool,
}

impl SoftKey {
    pub fn new(ed25519: bool, config: Config) -> Self {
        let rng = SystemRandom::new();
        let credential = if ed25519 {
            let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
            Credential::Ed25519(Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap())
        } else {
            let alg = &signature::ECDSA_P256_SHA256_ASN1_SIGNING;
            let pkcs8 = EcdsaKeyPair::generate_pkcs8(alg, &rng).unwrap();
            Credential::Ecdsa(EcdsaKeyPair::from_pkcs8(alg, pkcs8.as_ref(), &rng).unwrap())
        };
        let mut key_handle = vec![0; 96];
        rng.fill(&mut key_handle).unwrap();
        Self {
            application: "ssh:".into(),
            key_handle,
            credential,
            config,
            log: Arc::default(),
            counter: 41,
            retries: 8,
            cid: 0,
            incoming: None,
            outgoing: VecDeque::new(),
            key_agreement: None,
            pin_token: None,
            u2f_touched: false,
        }
    }

    /// The credential's public key: an uncompressed P-256 point, or the 32
    /// bytes of Ed25519.
    pub fn public_key(&self) -> Vec<u8> {
        match &self.credential {
            Credential::Ecdsa(pair) => pair.public_key().as_ref().to_vec(),
            Credential::Ed25519(pair) => pair.public_key().as_ref().to_vec(),
        }
    }

    fn sign(&self, data: &[u8]) -> Vec<u8> {
        match &self.credential {
            Credential::Ecdsa(pair) => pair
                .sign(&SystemRandom::new(), data)
                .unwrap()
                .as_ref()
                .to_vec(),
            Credential::Ed25519(pair) => pair.sign(data).as_ref().to_vec(),
        }
    }

    fn reply(&mut self, cid: u32, cmd: u8, data: &[u8]) {
        let mut report = [0; REPORT];
        report[..4].copy_from_slice(&cid.to_be_bytes());
        report[4] = cmd | 0x80;
        report[5..7].copy_from_slice(&(data.len() as u16).to_be_bytes());
        let first = data.len().min(REPORT - 7);
        report[7..7 + first].copy_from_slice(&data[..first]);
        self.outgoing.push_back(report);
        for (seq, chunk) in data[first..].chunks(REPORT - 5).enumerate() {
            let mut report = [0; REPORT];
            report[..4].copy_from_slice(&cid.to_be_bytes());
            report[4] = seq as u8;
            report[5..5 + chunk.len()].copy_from_slice(chunk);
            self.outgoing.push_back(report);
        }
    }

    fn handle(&mut self, cid: u32, cmd: u8, data: Vec<u8>) {
        match cmd {
            0x06 => {
                self.cid = 0x0102_0304;
                let mut answer = data;
                answer.extend_from_slice(&self.cid.to_be_bytes());
                let caps = if self.config.ctap2 { 0x04 } else { 0 }
                    | if self.config.u2f { 0 } else { 0x08 };
                answer.extend_from_slice(&[2, 5, 4, 1, caps]);
                self.reply(cid, 0x06, &answer);
            }
            0x10 if self.config.ctap2 => {
                let answer = match self.ctap2(&data) {
                    Ok(Some(value)) => [vec![0], value.encode()].concat(),
                    Ok(None) => vec![0],
                    Err(status) => vec![status],
                };
                self.reply(cid, 0x10, &answer);
            }
            0x03 if self.config.u2f => {
                let answer = self.u2f(&data);
                self.reply(cid, 0x03, &answer);
            }
            0x11 => {}
            // ERR_INVALID_CMD
            _ => self.reply(cid, 0x3f, &[0x01]),
        }
    }

    fn ctap2(&mut self, data: &[u8]) -> Result<Option<Value>, u8> {
        let (&command, params) = data.split_first().ok_or(0x01)?;
        let params = if params.is_empty() {
            Value::Map(vec![])
        } else {
            Value::decode(params).map_err(|_| 0x12u8)?
        };
        match command {
            0x04 => {
                let mut options = vec![(Value::text("rk"), Value::Bool(true))];
                options.push((Value::text("up"), Value::Bool(true)));
                if self.config.builtin_uv {
                    options.push((Value::text("uv"), Value::Bool(true)));
                }
                if self.config.pin_uv_auth_token {
                    options.push((Value::text("pinUvAuthToken"), Value::Bool(true)));
                }
                options.push((
                    Value::text("clientPin"),
                    Value::Bool(self.config.pin.is_some()),
                ));
                let protocols = self.config.pin_protocols.iter().map(|p| Value::Int(*p));
                Ok(Some(Value::Map(vec![
                    (
                        Value::Int(1),
                        Value::Array(vec![Value::text("U2F_V2"), Value::text("FIDO_2_0")]),
                    ),
                    (Value::Int(3), Value::Bytes(vec![0; 16])),
                    (Value::Int(4), Value::Map(options)),
                    (Value::Int(6), Value::Array(protocols.collect())),
                ])))
            }
            0x02 => self.get_assertion(&params),
            0x06 => self.client_pin(&params),
            _ => Err(0x01),
        }
    }

    fn get_assertion(&mut self, params: &Value) -> Result<Option<Value>, u8> {
        let rp_id = match params.get(1) {
            Some(Value::Text(rp_id)) => rp_id.clone(),
            _ => return Err(0x14),
        };
        let cdh = params
            .get(2)
            .and_then(Value::as_bytes)
            .ok_or(0x14u8)?
            .to_vec();
        let allowed = params
            .get(3)
            .and_then(Value::as_array)
            .unwrap_or_default()
            .iter()
            .any(|c| c.get_text("id").and_then(Value::as_bytes) == Some(&self.key_handle[..]));
        let option = |name| {
            params
                .get(5)
                .and_then(|o| o.get_text(name))
                .and_then(Value::as_bool)
        };
        let up = option("up").unwrap_or(true);
        let mut uv = option("uv").unwrap_or(false);
        if uv && !self.config.builtin_uv {
            return Err(ctap::CTAP2_ERR_UNSUPPORTED_OPTION);
        }
        if let Some(auth) = params.get(6).and_then(Value::as_bytes) {
            let version = params.get(7).and_then(Value::as_int).ok_or(0x14u8)? as u8;
            let token = self.pin_token.as_ref().ok_or(0x33u8)?;
            if soft_protocol(version, Vec::new()).authenticate(token, &cdh) != auth {
                return Err(0x33); // PIN_AUTH_INVALID
            }
            uv = true;
        } else if self.config.always_uv && up {
            return Err(ctap::CTAP2_ERR_PIN_REQUIRED);
        }
        if !up {
            self.log.lock().unwrap().probes += 1;
        }
        if rp_id != self.application || !allowed {
            return Err(ctap::CTAP2_ERR_NO_CREDENTIALS);
        }
        self.counter += 1;
        let flags = u8::from(up) | if uv { 0x04 } else { 0 };
        let mut auth_data = ctap::sha256(rp_id.as_bytes()).to_vec();
        auth_data.push(flags);
        auth_data.extend_from_slice(&self.counter.to_be_bytes());
        let signature = self.sign(&[&auth_data[..], &cdh].concat());
        if up {
            self.log.lock().unwrap().assertions += 1;
        }
        Ok(Some(Value::Map(vec![
            (Value::Int(2), Value::Bytes(auth_data)),
            (Value::Int(3), Value::Bytes(signature)),
        ])))
    }

    fn client_pin(&mut self, params: &Value) -> Result<Option<Value>, u8> {
        let version = params.get(1).and_then(Value::as_int).ok_or(0x14u8)?;
        if !self.config.pin_protocols.contains(&version) {
            return Err(0x14);
        }
        let version = version as u8;
        match params.get(2).and_then(Value::as_int) {
            // getPINRetries
            Some(1) => Ok(Some(Value::Map(vec![(
                Value::Int(3),
                Value::Int(self.retries),
            )]))),
            // getKeyAgreement
            Some(2) => {
                let private = agreement::EphemeralPrivateKey::generate(
                    &agreement::ECDH_P256,
                    &SystemRandom::new(),
                )
                .unwrap();
                let public = private.compute_public_key().unwrap();
                let public = public.as_ref();
                self.key_agreement = Some((version, private));
                Ok(Some(Value::Map(vec![(
                    Value::Int(1),
                    ctap::cose_key(&public[1..33], &public[33..65]),
                )])))
            }
            // getPinToken, getPinUvAuthTokenUsingPinWithPermissions
            Some(sub @ (5 | 9)) => {
                if sub == 9 && !self.config.pin_uv_auth_token {
                    return Err(0x01);
                }
                if sub == 9 && params.get(9).and_then(Value::as_int) != Some(0x02) {
                    return Err(0x14);
                }
                self.log.lock().unwrap().pin_tries += 1;
                let pin = self.config.pin.clone().ok_or(ctap::CTAP2_ERR_PIN_NOT_SET)?;
                if self.retries == 0 {
                    return Err(ctap::CTAP2_ERR_PIN_BLOCKED);
                }
                let (agreed, private) = self.key_agreement.take().ok_or(0x14u8)?;
                if agreed != version {
                    return Err(0x14);
                }
                let peer = params.get(3).ok_or(0x14u8)?;
                let (x, y) = ctap::cose_point(peer).map_err(|_| 0x14u8)?;
                let peer = agreement::UnparsedPublicKey::new(
                    &agreement::ECDH_P256,
                    [&[0x04][..], x, y].concat(),
                );
                let shared =
                    agreement::agree_ephemeral(private, &peer, |z| PinProtocol::kdf(version, z))
                        .map_err(|_| 0x14u8)?;
                let protocol = soft_protocol(version, shared);
                let pin_hash_enc = params.get(6).and_then(Value::as_bytes).ok_or(0x14u8)?;
                let pin_hash = protocol.decrypt(pin_hash_enc).map_err(|_| 0x14u8)?;
                if pin_hash != ctap::sha256(pin.as_bytes())[..16] {
                    self.retries -= 1;
                    return Err(ctap::CTAP2_ERR_PIN_INVALID);
                }
                self.retries = 8;
                let mut token = vec![0; 32];
                SystemRandom::new().fill(&mut token).unwrap();
                let encrypted = protocol.encrypt(&token).unwrap();
                self.pin_token = Some(token);
                Ok(Some(Value::Map(vec![(
                    Value::Int(2),
                    Value::Bytes(encrypted),
                )])))
            }
            _ => Err(0x14),
        }
    }

    fn u2f(&mut self, apdu: &[u8]) -> Vec<u8> {
        let sw = |sw: u16| sw.to_be_bytes().to_vec();
        if apdu.len() < 7 || apdu[1] != 0x02 {
            return sw(0x6d00);
        }
        let len = usize::from(u16::from_be_bytes([apdu[5], apdu[6]]));
        let Some(data) = apdu.get(7..7 + len) else {
            return sw(0x6700);
        };
        if data.len() < 65 || data.len() != 65 + usize::from(data[64]) {
            return sw(0x6700);
        }
        let (challenge, app, handle) = (&data[..32], &data[32..64], &data[65..]);
        if app != ctap::sha256(self.application.as_bytes()) || handle != self.key_handle {
            return sw(0x6a80);
        }
        if apdu[2] == 0x07 {
            self.log.lock().unwrap().probes += 1;
            return sw(0x6985);
        }
        if !std::mem::replace(&mut self.u2f_touched, true) {
            return sw(0x6985);
        }
        self.counter += 1;
        let presence = [&[0x01][..], &self.counter.to_be_bytes()].concat();
        let signature = self.sign(&[app, &presence, challenge].concat());
        self.log.lock().unwrap().assertions += 1;
        [presence, signature, sw(0x9000)].concat()
    }
}

/// A PIN protocol with a known shared secret (`PinProtocol::agree` makes
/// its own).
fn soft_protocol(version: u8, shared: Vec<u8>) -> PinProtocol {
    PinProtocol::with_shared(version, shared)
}

impl Device for SoftKey {
    fn write(&mut self, report: &[u8; REPORT]) -> io::Result<()> {
        let cid = u32::from_be_bytes(report[..4].try_into().unwrap());
        if report[4] & 0x80 != 0 {
            let len = usize::from(u16::from_be_bytes([report[5], report[6]]));
            let first = len.min(REPORT - 7);
            self.incoming = Some((cid, report[4] & 0x7f, len, report[7..7 + first].to_vec()));
        } else if let Some((_, _, len, data)) = &mut self.incoming {
            let take = (*len - data.len()).min(REPORT - 5);
            data.extend_from_slice(&report[5..5 + take]);
        }
        if let Some((cid, cmd, len, data)) = self.incoming.take() {
            if data.len() < len {
                self.incoming = Some((cid, cmd, len, data));
            } else {
                // A keepalive first, as keys send while they wait.
                if cmd == 0x10 && data.first() == Some(&0x02) {
                    let mut keepalive = [0; REPORT];
                    keepalive[..4].copy_from_slice(&cid.to_be_bytes());
                    keepalive[4] = 0xbb;
                    keepalive[6] = 1;
                    keepalive[7] = 2;
                    self.outgoing.push_back(keepalive);
                }
                self.handle(cid, cmd, data);
            }
        }
        Ok(())
    }

    fn read(&mut self, timeout: Duration) -> io::Result<Option<[u8; REPORT]>> {
        let report = self.outgoing.pop_front();
        if report.is_none() {
            std::thread::sleep(timeout.min(Duration::from_millis(10)));
        }
        Ok(report)
    }
}
