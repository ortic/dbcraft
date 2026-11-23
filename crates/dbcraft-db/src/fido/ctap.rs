//! A security key over USB HID: CTAPHID framing, CTAP2's getAssertion
//! (with PIN protocols one and two for keys that verify the user) and U2F's
//! authenticate for keys that only speak U2F. This is what libfido2 does
//! for OpenSSH; the device itself is the platform's ([`Device`]).

use std::fmt;
use std::io;
use std::time::{Duration, Instant};

use aes::Aes256;
use aes::cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
use ring::agreement;
use ring::digest::{SHA256, digest};
use ring::hkdf;
use ring::hmac;
use ring::rand::{SecureRandom, SystemRandom};
use tracing::debug;

use super::cbor::Value;
use super::{Assertion, Request, TOUCH_TIMEOUT};

/// A HID report of a FIDO device, without the report ID.
pub const REPORT: usize = 64;

/// A FIDO HID device of the platform.
pub trait Device {
    fn write(&mut self, report: &[u8; REPORT]) -> io::Result<()>;
    /// The next input report, `None` once `timeout` passed without one.
    fn read(&mut self, timeout: Duration) -> io::Result<Option<[u8; REPORT]>>;
}

const BROADCAST: u32 = 0xffff_ffff;
const CMD_MSG: u8 = 0x03;
const CMD_INIT: u8 = 0x06;
const CMD_CBOR: u8 = 0x10;
const CMD_CANCEL: u8 = 0x11;
const CMD_KEEPALIVE: u8 = 0x3b;
const CMD_ERROR: u8 = 0x3f;
const CAP_CBOR: u8 = 0x04;
const CAP_NMSG: u8 = 0x08;
/// The longest message: one init packet and 128 continuation packets.
const MAX_MESSAGE: usize = (REPORT - 7) + 128 * (REPORT - 5);

const GET_ASSERTION: u8 = 0x02;
const GET_INFO: u8 = 0x04;
const CLIENT_PIN: u8 = 0x06;

pub const CTAP2_ERR_OPERATION_DENIED: u8 = 0x27;
pub const CTAP2_ERR_UNSUPPORTED_OPTION: u8 = 0x2b;
pub const CTAP2_ERR_NO_CREDENTIALS: u8 = 0x2e;
pub const CTAP2_ERR_USER_ACTION_TIMEOUT: u8 = 0x2f;
pub const CTAP2_ERR_PIN_INVALID: u8 = 0x31;
pub const CTAP2_ERR_PIN_BLOCKED: u8 = 0x32;
pub const CTAP2_ERR_PIN_AUTH_BLOCKED: u8 = 0x34;
pub const CTAP2_ERR_PIN_NOT_SET: u8 = 0x35;
pub const CTAP2_ERR_PIN_REQUIRED: u8 = 0x36;
pub const CTAP2_ERR_PIN_POLICY_VIOLATION: u8 = 0x37;
pub const CTAP2_ERR_UV_BLOCKED: u8 = 0x3c;

const SW_NO_ERROR: u16 = 0x9000;
const SW_CONDITIONS_NOT_SATISFIED: u16 = 0x6985;
const SW_WRONG_DATA: u16 = 0x6a80;

/// For commands that don't wait for the user.
const COMMAND_TIMEOUT: Duration = Duration::from_secs(10);
const U2F_POLL: Duration = Duration::from_millis(200);

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Timeout,
    Protocol(&'static str),
    /// A CTAPHID error code.
    Hid(u8),
    /// A CTAP2 status code.
    Ctap(u8),
    /// A U2F status word.
    U2f(u16),
    /// The key verifies the user, and there is neither a PIN nor a built-in
    /// verification (fingerprint) to do that with.
    PinNeeded,
    /// The PIN isn't the key's; with the tries it has left.
    WrongPin(Option<i64>),
    /// The key can't do what the key file asks for.
    Unsupported(&'static str),
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<super::cbor::Error> for Error {
    fn from(_: super::cbor::Error) -> Self {
        Self::Protocol("malformed CBOR")
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "{e}"),
            Self::Timeout => f.write_str("no answer in time"),
            Self::Protocol(what) => write!(f, "unexpected answer: {what}"),
            Self::Hid(code) => write!(f, "HID error 0x{code:02x}"),
            Self::Ctap(CTAP2_ERR_NO_CREDENTIALS) => f.write_str("it doesn't hold this key"),
            Self::Ctap(CTAP2_ERR_USER_ACTION_TIMEOUT) => f.write_str("it wasn't touched in time"),
            Self::Ctap(CTAP2_ERR_OPERATION_DENIED) => f.write_str("signing was denied"),
            Self::Ctap(CTAP2_ERR_PIN_BLOCKED) => {
                f.write_str("its PIN is blocked after too many wrong tries")
            }
            Self::Ctap(CTAP2_ERR_PIN_AUTH_BLOCKED) => f.write_str(
                "it takes no more PINs after three wrong ones: unplug it, plug it in again",
            ),
            Self::Ctap(CTAP2_ERR_PIN_NOT_SET) => f.write_str("it has no PIN set"),
            Self::Ctap(CTAP2_ERR_PIN_POLICY_VIOLATION) => {
                f.write_str("the PIN doesn't meet its requirements")
            }
            Self::Ctap(CTAP2_ERR_UNSUPPORTED_OPTION) => {
                f.write_str("it can't do what the key file asks for")
            }
            Self::Ctap(CTAP2_ERR_UV_BLOCKED) => f.write_str("its fingerprint check is blocked"),
            Self::Ctap(code) => write!(f, "CTAP2 error 0x{code:02x}"),
            Self::U2f(SW_WRONG_DATA) => f.write_str("it doesn't hold this key"),
            Self::U2f(sw) => write!(f, "U2F error 0x{sw:04x}"),
            Self::PinNeeded => f.write_str("it needs its PIN: enter it as the SSH password"),
            Self::WrongPin(Some(left)) => {
                write!(
                    f,
                    "the PIN is wrong ({left} tries left before the key locks)"
                )
            }
            Self::WrongPin(None) => f.write_str("the PIN is wrong"),
            Self::Unsupported(what) => f.write_str(what),
        }
    }
}

/// A CTAPHID channel to a device.
pub struct Channel<D> {
    device: D,
    cid: u32,
    caps: u8,
}

impl<D: Device> Channel<D> {
    pub fn open(mut device: D) -> Result<Self, Error> {
        let mut nonce = [0; 8];
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| Error::Protocol("no random numbers"))?;
        send(&mut device, BROADCAST, CMD_INIT, &nonce)?;
        let deadline = Instant::now() + COMMAND_TIMEOUT;
        loop {
            let (cmd, data) = receive(&mut device, BROADCAST, deadline)?;
            // Another program's INIT answer, or one to an earlier nonce.
            if cmd != CMD_INIT || data.len() < 17 || data[..8] != nonce {
                continue;
            }
            let cid = u32::from_be_bytes(data[8..12].try_into().expect("4 bytes"));
            return Ok(Self {
                device,
                cid,
                caps: data[16],
            });
        }
    }

    pub fn ctap2(&self) -> bool {
        self.caps & CAP_CBOR != 0
    }

    pub fn u2f(&self) -> bool {
        self.caps & CAP_NMSG == 0
    }

    pub fn transact(&mut self, cmd: u8, data: &[u8], timeout: Duration) -> Result<Vec<u8>, Error> {
        send(&mut self.device, self.cid, cmd, data)?;
        let deadline = Instant::now() + timeout;
        loop {
            match receive(&mut self.device, self.cid, deadline) {
                Ok((CMD_KEEPALIVE, _)) => {}
                Ok((CMD_ERROR, data)) => {
                    return Err(Error::Hid(data.first().copied().unwrap_or(0)));
                }
                Ok((reply, data)) if reply == cmd => return Ok(data),
                Ok(_) => return Err(Error::Protocol("an answer to another command")),
                Err(Error::Timeout) => {
                    // Stops the key from waiting for a touch nobody expects.
                    let _ = send(&mut self.device, self.cid, CMD_CANCEL, &[]);
                    return Err(Error::Timeout);
                }
                Err(e) => return Err(e),
            }
        }
    }
}

fn send(device: &mut impl Device, cid: u32, cmd: u8, data: &[u8]) -> Result<(), Error> {
    if data.len() > MAX_MESSAGE {
        return Err(Error::Protocol("request too long"));
    }
    let mut report = [0; REPORT];
    report[..4].copy_from_slice(&cid.to_be_bytes());
    report[4] = cmd | 0x80;
    report[5..7].copy_from_slice(&(data.len() as u16).to_be_bytes());
    let first = data.len().min(REPORT - 7);
    report[7..7 + first].copy_from_slice(&data[..first]);
    device.write(&report)?;
    for (seq, chunk) in data[first..].chunks(REPORT - 5).enumerate() {
        let mut report = [0; REPORT];
        report[..4].copy_from_slice(&cid.to_be_bytes());
        report[4] = seq as u8;
        report[5..5 + chunk.len()].copy_from_slice(chunk);
        device.write(&report)?;
    }
    Ok(())
}

/// The next message on `cid`: its command and data.
fn receive(device: &mut impl Device, cid: u32, deadline: Instant) -> Result<(u8, Vec<u8>), Error> {
    let mut next = || -> Result<[u8; REPORT], Error> {
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(Error::Timeout);
            }
            if let Some(report) = device.read(left)?
                && report[..4] == cid.to_be_bytes()
            {
                return Ok(report);
            }
        }
    };
    let report = loop {
        let report = next()?;
        // A continuation packet without its start: skip it.
        if report[4] & 0x80 != 0 {
            break report;
        }
    };
    let cmd = report[4] & 0x7f;
    let len = usize::from(u16::from_be_bytes([report[5], report[6]]));
    if len > MAX_MESSAGE {
        return Err(Error::Protocol("answer too long"));
    }
    let mut data = Vec::with_capacity(len);
    data.extend_from_slice(&report[7..7 + len.min(REPORT - 7)]);
    let mut seq = 0;
    while data.len() < len {
        let report = next()?;
        if report[4] != seq {
            return Err(Error::Protocol("continuation packet out of sequence"));
        }
        seq += 1;
        let take = (len - data.len()).min(REPORT - 5);
        data.extend_from_slice(&report[5..5 + take]);
    }
    Ok((cmd, data))
}

/// What a CTAP2 key says about itself.
#[derive(Debug, Default)]
pub struct Info {
    options: Vec<(String, bool)>,
    pin_protocols: Vec<i64>,
}

impl Info {
    fn option(&self, name: &str) -> Option<bool> {
        self.options
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| *v)
    }
}

/// A security key, over a channel.
pub struct Authenticator<D> {
    channel: Channel<D>,
    info: Option<Info>,
}

impl<D: Device> Authenticator<D> {
    pub fn open(device: D) -> Result<Self, Error> {
        Ok(Self {
            channel: Channel::open(device)?,
            info: None,
        })
    }

    fn cbor(
        &mut self,
        command: u8,
        params: Option<Value>,
        timeout: Duration,
    ) -> Result<Option<Value>, Error> {
        let mut request = vec![command];
        if let Some(params) = params {
            request.extend(params.encode());
        }
        let answer = self.channel.transact(CMD_CBOR, &request, timeout)?;
        match answer.split_first() {
            Some((0, [])) => Ok(None),
            Some((0, body)) => Ok(Some(Value::decode(body)?)),
            Some((&status, _)) => Err(Error::Ctap(status)),
            None => Err(Error::Protocol("empty CTAP2 answer")),
        }
    }

    fn info(&mut self) -> Result<&Info, Error> {
        if self.info.is_none() {
            let answer = self
                .cbor(GET_INFO, None, COMMAND_TIMEOUT)?
                .ok_or(Error::Protocol("no getInfo answer"))?;
            let mut info = Info::default();
            if let Some(Value::Map(options)) = answer.get(4) {
                for (name, value) in options {
                    if let (Value::Text(name), Value::Bool(value)) = (name, value) {
                        info.options.push((name.clone(), *value));
                    }
                }
            }
            if let Some(protocols) = answer.get(6).and_then(Value::as_array) {
                info.pin_protocols = protocols.iter().filter_map(Value::as_int).collect();
            }
            debug!(?info, "security key");
            self.info = Some(info);
        }
        Ok(self.info.as_ref().expect("just set"))
    }

    /// Whether the key holds the credential, asked without a touch (to
    /// pick the right one of several keys).
    pub fn holds(&mut self, request: &Request) -> Result<bool, Error> {
        if self.channel.ctap2() {
            let params = assertion_params(request, &[0; 32], &[("up", false)], None);
            match self.cbor(GET_ASSERTION, Some(params), COMMAND_TIMEOUT) {
                Ok(_) => Ok(true),
                Err(Error::Ctap(CTAP2_ERR_NO_CREDENTIALS)) => Ok(false),
                // Keys that always verify the user may not even look.
                Err(Error::Ctap(CTAP2_ERR_PIN_REQUIRED)) => Ok(true),
                Err(e) => Err(e),
            }
        } else {
            match self.u2f_authenticate(0x07, request, &[0; 32]) {
                Err(Error::U2f(SW_CONDITIONS_NOT_SATISFIED)) => Ok(true),
                Err(Error::U2f(SW_WRONG_DATA)) => Ok(false),
                Ok(_) => Ok(true),
                Err(e) => Err(e),
            }
        }
    }

    /// Signs `request.message`, waiting for the touch.
    pub fn sign(&mut self, request: &Request) -> Result<Assertion, Error> {
        let client_data_hash = sha256(request.message);
        if self.channel.ctap2() {
            self.ctap2_sign(request, &client_data_hash)
        } else if request.user_verification {
            Err(Error::Unsupported(
                "the key file asks to verify the user, which a U2F key can't",
            ))
        } else {
            self.u2f_sign(request, &client_data_hash)
        }
    }

    fn ctap2_sign(
        &mut self,
        request: &Request,
        client_data_hash: &[u8],
    ) -> Result<Assertion, Error> {
        let mut options = Vec::new();
        if !request.user_presence {
            options.push(("up", false));
        }
        let with_pin = if request.user_verification {
            if let Some(pin) = request.pin {
                Some(pin)
            } else if self.info()?.option("uv") == Some(true) {
                // A fingerprint key verifies by itself.
                options.push(("uv", true));
                None
            } else {
                return Err(Error::PinNeeded);
            }
        } else {
            None
        };
        let answer = match with_pin {
            Some(pin) => self.ctap2_sign_with_pin(request, client_data_hash, &options, pin)?,
            None => {
                let params = assertion_params(request, client_data_hash, &options, None);
                match self.cbor(GET_ASSERTION, Some(params), TOUCH_TIMEOUT) {
                    // Keys set to always verify the user ask for the PIN
                    // even for keys that don't.
                    Err(Error::Ctap(CTAP2_ERR_PIN_REQUIRED)) => match request.pin {
                        Some(pin) => {
                            self.ctap2_sign_with_pin(request, client_data_hash, &options, pin)?
                        }
                        None => return Err(Error::PinNeeded),
                    },
                    answer => answer?,
                }
            }
        };
        let answer = answer.ok_or(Error::Protocol("no getAssertion answer"))?;
        let auth_data = answer
            .get(2)
            .and_then(Value::as_bytes)
            .ok_or(Error::Protocol("no authenticator data"))?;
        let signature = answer
            .get(3)
            .and_then(Value::as_bytes)
            .ok_or(Error::Protocol("no signature"))?;
        assertion(request, auth_data, signature)
    }

    fn ctap2_sign_with_pin(
        &mut self,
        request: &Request,
        client_data_hash: &[u8],
        options: &[(&str, bool)],
        pin: &str,
    ) -> Result<Option<Value>, Error> {
        // Short ones would cost a try on some keys.
        if pin.chars().count() < 4 || pin.len() > 63 {
            return Err(Error::Ctap(CTAP2_ERR_PIN_POLICY_VIOLATION));
        }
        let (protocol, token) = self.pin_token(pin, request.application)?;
        let auth = (
            protocol.version,
            protocol.authenticate(&token, client_data_hash),
        );
        let options: Vec<_> = options
            .iter()
            .filter(|(name, _)| *name != "uv")
            .copied()
            .collect();
        let params = assertion_params(request, client_data_hash, &options, Some(auth));
        self.cbor(GET_ASSERTION, Some(params), TOUCH_TIMEOUT)
    }

    /// A PIN/UV auth token from the PIN, and the protocol it is for.
    fn pin_token(&mut self, pin: &str, rp_id: &str) -> Result<(PinProtocol, Vec<u8>), Error> {
        let info = self.info()?;
        if info.option("clientPin") != Some(true) {
            return Err(Error::Ctap(CTAP2_ERR_PIN_NOT_SET));
        }
        let version = if info.pin_protocols.contains(&2) {
            2
        } else {
            1
        };
        let permissions = version == 2 && info.option("pinUvAuthToken") == Some(true);
        let peer = self
            .cbor(
                CLIENT_PIN,
                Some(int_map(vec![(1, Value::Int(version)), (2, Value::Int(2))])),
                COMMAND_TIMEOUT,
            )?
            .and_then(|answer| answer.get(1).cloned())
            .ok_or(Error::Protocol("no key agreement"))?;
        let (protocol, platform_key) = PinProtocol::agree(version as u8, &peer)?;
        let pin_hash = &sha256(pin.as_bytes())[..16];
        let mut params = vec![
            (1, Value::Int(version)),
            (2, Value::Int(if permissions { 9 } else { 5 })),
            (3, platform_key),
            (6, Value::Bytes(protocol.encrypt(pin_hash)?)),
        ];
        if permissions {
            // getAssertion, for this application only.
            params.push((9, Value::Int(0x02)));
            params.push((10, Value::text(rp_id)));
        }
        let answer = match self.cbor(CLIENT_PIN, Some(int_map(params)), COMMAND_TIMEOUT) {
            Err(Error::Ctap(CTAP2_ERR_PIN_INVALID)) => {
                return Err(Error::WrongPin(self.pin_retries(version).ok()));
            }
            answer => answer?,
        };
        let encrypted = answer
            .as_ref()
            .and_then(|answer| answer.get(2))
            .and_then(Value::as_bytes)
            .ok_or(Error::Protocol("no PIN token"))?;
        let token = protocol.decrypt(encrypted)?;
        Ok((protocol, token))
    }

    fn pin_retries(&mut self, version: i64) -> Result<i64, Error> {
        self.cbor(
            CLIENT_PIN,
            Some(int_map(vec![(1, Value::Int(version)), (2, Value::Int(1))])),
            COMMAND_TIMEOUT,
        )?
        .and_then(|answer| answer.get(3).and_then(Value::as_int))
        .ok_or(Error::Protocol("no PIN retries"))
    }

    fn u2f_sign(&mut self, request: &Request, client_data_hash: &[u8]) -> Result<Assertion, Error> {
        let deadline = Instant::now() + TOUCH_TIMEOUT;
        loop {
            match self.u2f_authenticate(0x03, request, client_data_hash) {
                // Waits for the touch: U2F keys say so instead of waiting.
                Err(Error::U2f(SW_CONDITIONS_NOT_SATISFIED)) if Instant::now() < deadline => {
                    std::thread::sleep(U2F_POLL);
                }
                Err(Error::U2f(SW_CONDITIONS_NOT_SATISFIED)) => {
                    return Err(Error::Ctap(CTAP2_ERR_USER_ACTION_TIMEOUT));
                }
                Err(e) => return Err(e),
                Ok(answer) => {
                    // The user presence byte and the counter are what
                    // CTAP2's authenticator data has after the hash.
                    if answer.len() < 5 {
                        return Err(Error::Protocol("U2F signature too short"));
                    }
                    let auth_data =
                        [&sha256(request.application.as_bytes())[..], &answer[..5]].concat();
                    return assertion(request, &auth_data, &answer[5..]);
                }
            }
        }
    }

    /// U2F_AUTHENTICATE with `control` 0x03 (sign) or 0x07 (check only).
    fn u2f_authenticate(
        &mut self,
        control: u8,
        request: &Request,
        challenge: &[u8],
    ) -> Result<Vec<u8>, Error> {
        if !self.channel.u2f() {
            return Err(Error::Unsupported("the key speaks neither CTAP2 nor U2F"));
        }
        let handle = request.key_handle;
        let len = u8::try_from(handle.len()).map_err(|_| Error::Protocol("key handle too long"))?;
        let mut data = Vec::with_capacity(65 + handle.len());
        data.extend_from_slice(challenge);
        data.extend_from_slice(&sha256(request.application.as_bytes()));
        data.push(len);
        data.extend_from_slice(handle);
        // Extended length: Lc in three bytes, Le in two.
        let mut apdu = vec![0x00, 0x02, control, 0x00, 0x00];
        apdu.extend_from_slice(&(data.len() as u16).to_be_bytes());
        apdu.extend_from_slice(&data);
        apdu.extend_from_slice(&[0x00, 0x00]);
        let mut answer = self.channel.transact(CMD_MSG, &apdu, COMMAND_TIMEOUT)?;
        if answer.len() < 2 {
            return Err(Error::Protocol("U2F answer without status"));
        }
        let sw = answer.split_off(answer.len() - 2);
        match u16::from_be_bytes([sw[0], sw[1]]) {
            SW_NO_ERROR => Ok(answer),
            sw => Err(Error::U2f(sw)),
        }
    }
}

/// getAssertion's parameters, keys in canonical order.
fn assertion_params(
    request: &Request,
    client_data_hash: &[u8],
    options: &[(&str, bool)],
    pin_auth: Option<(u8, Vec<u8>)>,
) -> Value {
    let credential = Value::Map(vec![
        (Value::text("id"), Value::Bytes(request.key_handle.to_vec())),
        (Value::text("type"), Value::text("public-key")),
    ]);
    let mut params = vec![
        (1, Value::text(request.application)),
        (2, Value::Bytes(client_data_hash.to_vec())),
        (3, Value::Array(vec![credential])),
    ];
    if !options.is_empty() {
        let options = options
            .iter()
            .map(|(name, value)| (Value::text(name), Value::Bool(*value)))
            .collect();
        params.push((5, Value::Map(options)));
    }
    if let Some((version, auth)) = pin_auth {
        params.push((6, Value::Bytes(auth)));
        params.push((7, Value::Int(i64::from(version))));
    }
    int_map(params)
}

fn int_map(entries: Vec<(i64, Value)>) -> Value {
    Value::Map(
        entries
            .into_iter()
            .map(|(k, v)| (Value::Int(k), v))
            .collect(),
    )
}

/// The assertion in authenticator data `auth_data` (rpIdHash, flags,
/// counter) and `signature`.
fn assertion(request: &Request, auth_data: &[u8], signature: &[u8]) -> Result<Assertion, Error> {
    if auth_data.len() < 37 {
        return Err(Error::Protocol("authenticator data too short"));
    }
    if auth_data[..32] != sha256(request.application.as_bytes()) {
        return Err(Error::Protocol("signed for another application"));
    }
    Ok(Assertion {
        flags: auth_data[32],
        counter: u32::from_be_bytes(auth_data[33..37].try_into().expect("4 bytes")),
        signature: signature.to_vec(),
    })
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    digest(&SHA256, data)
        .as_ref()
        .try_into()
        .expect("SHA-256 has 32 bytes")
}

/// PIN/UV auth protocol one or two (CTAP 2.1, 6.5.6 and 6.5.7): a secret
/// shared with the key by ECDH on P-256.
pub struct PinProtocol {
    pub version: u8,
    /// Protocol one: SHA-256 of the shared point's x. Two: the HMAC key
    /// then the AES key.
    shared: Vec<u8>,
}

impl PinProtocol {
    #[cfg(test)]
    pub fn with_shared(version: u8, shared: Vec<u8>) -> Self {
        Self { version, shared }
    }

    /// Agrees on a secret with the key's COSE key `peer`; the platform's
    /// COSE key goes back to the key.
    pub fn agree(version: u8, peer: &Value) -> Result<(Self, Value), Error> {
        let (x, y) = cose_point(peer)?;
        let rng = SystemRandom::new();
        let private = agreement::EphemeralPrivateKey::generate(&agreement::ECDH_P256, &rng)
            .map_err(|_| Error::Protocol("no ECDH key"))?;
        let public = private
            .compute_public_key()
            .map_err(|_| Error::Protocol("no ECDH key"))?;
        let peer =
            agreement::UnparsedPublicKey::new(&agreement::ECDH_P256, [&[0x04][..], x, y].concat());
        let shared = agreement::agree_ephemeral(private, &peer, |z| Self::kdf(version, z))
            .map_err(|_| Error::Protocol("the key's ECDH key isn't on P-256"))?;
        let public = public.as_ref();
        Ok((
            Self { version, shared },
            cose_key(&public[1..33], &public[33..65]),
        ))
    }

    pub fn kdf(version: u8, z: &[u8]) -> Vec<u8> {
        if version == 1 {
            return sha256(z).to_vec();
        }
        let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, &[0; 32]).extract(z);
        let mut shared = vec![0; 64];
        for (info, out) in [&b"CTAP2 HMAC key"[..], b"CTAP2 AES key"]
            .iter()
            .zip(shared.chunks_mut(32))
        {
            prk.expand(&[info], hkdf::HKDF_SHA256)
                .and_then(|okm| okm.fill(out))
                .expect("32 bytes from HKDF-SHA-256");
        }
        shared
    }

    fn aes_key(&self) -> &[u8] {
        if self.version == 1 {
            &self.shared
        } else {
            &self.shared[32..]
        }
    }

    pub fn encrypt(&self, plain: &[u8]) -> Result<Vec<u8>, Error> {
        let mut iv = [0; 16];
        if self.version == 2 {
            SystemRandom::new()
                .fill(&mut iv)
                .map_err(|_| Error::Protocol("no random numbers"))?;
        }
        let mut out = if self.version == 2 {
            iv.to_vec()
        } else {
            Vec::new()
        };
        out.extend(cbc_encrypt(self.aes_key(), &iv, plain)?);
        Ok(out)
    }

    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
        if self.version == 1 {
            cbc_decrypt(self.aes_key(), &[0; 16], data)
        } else if data.len() >= 16 {
            let (iv, data) = data.split_at(16);
            cbc_decrypt(self.aes_key(), iv.try_into().expect("16 bytes"), data)
        } else {
            Err(Error::Protocol("encrypted data too short"))
        }
    }

    /// HMAC-SHA-256 of `message` with `key` (the HMAC part of a shared
    /// secret, or a PIN token): its first 16 bytes in protocol one.
    pub fn authenticate(&self, key: &[u8], message: &[u8]) -> Vec<u8> {
        let key = &key[..key.len().min(32)];
        let tag = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, key), message);
        let tag = tag.as_ref();
        if self.version == 1 {
            tag[..16].to_vec()
        } else {
            tag.to_vec()
        }
    }
}

/// x and y of a COSE EC2 key on P-256.
pub fn cose_point(key: &Value) -> Result<(&[u8], &[u8]), Error> {
    let x = key.get(-2).and_then(Value::as_bytes);
    let y = key.get(-3).and_then(Value::as_bytes);
    match (key.get(1), key.get(-1), x, y) {
        (Some(Value::Int(2)), Some(Value::Int(1)), Some(x), Some(y))
            if x.len() == 32 && y.len() == 32 =>
        {
            Ok((x, y))
        }
        _ => Err(Error::Protocol("not a P-256 COSE key")),
    }
}

/// A COSE key for ECDH on P-256, as the PIN protocols send it.
pub fn cose_key(x: &[u8], y: &[u8]) -> Value {
    int_map(vec![
        (1, Value::Int(2)),
        (3, Value::Int(-25)),
        (-1, Value::Int(1)),
        (-2, Value::Bytes(x.to_vec())),
        (-3, Value::Bytes(y.to_vec())),
    ])
}

fn aes(key: &[u8]) -> Result<Aes256, Error> {
    Aes256::new_from_slice(key).map_err(|_| Error::Protocol("AES key length"))
}

pub fn cbc_encrypt(key: &[u8], iv: &[u8; 16], plain: &[u8]) -> Result<Vec<u8>, Error> {
    if !plain.len().is_multiple_of(16) {
        return Err(Error::Protocol("not whole AES blocks"));
    }
    let cipher = aes(key)?;
    let mut chain = *iv;
    let mut out = Vec::with_capacity(plain.len());
    for block in plain.chunks(16) {
        let mut b = aes::Block::default();
        for (i, byte) in block.iter().enumerate() {
            b[i] = byte ^ chain[i];
        }
        cipher.encrypt_block(&mut b);
        chain.copy_from_slice(&b);
        out.extend_from_slice(&b);
    }
    Ok(out)
}

pub fn cbc_decrypt(key: &[u8], iv: &[u8; 16], data: &[u8]) -> Result<Vec<u8>, Error> {
    if !data.len().is_multiple_of(16) {
        return Err(Error::Protocol("not whole AES blocks"));
    }
    let cipher = aes(key)?;
    let mut chain = *iv;
    let mut out = Vec::with_capacity(data.len());
    for block in data.chunks(16) {
        let mut b = aes::Block::default();
        b.copy_from_slice(block);
        cipher.decrypt_block(&mut b);
        for (i, byte) in b.iter().enumerate() {
            out.push(byte ^ chain[i]);
        }
        chain.copy_from_slice(block);
    }
    Ok(out)
}
