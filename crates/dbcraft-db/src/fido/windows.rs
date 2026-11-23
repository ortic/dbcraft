//! Security keys on Windows, through the WebAuthn API (webauthn.dll, from
//! Windows 10 1903): Windows doesn't let programs talk to FIDO devices
//! directly, and shows its own dialog for the touch and the PIN. This is
//! what Windows' OpenSSH does (libfido2's "winhello").
//!
//! The DLL is loaded when a key signs, so DbCraft still starts on systems
//! without it.

use std::sync::OnceLock;

use windows_sys::Win32::Foundation::HWND;
use windows_sys::Win32::Networking::WindowsWebServices::{
    WEBAUTHN_ASSERTION, WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS,
    WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_1, WEBAUTHN_CLIENT_DATA,
    WEBAUTHN_CLIENT_DATA_CURRENT_VERSION, WEBAUTHN_CREDENTIAL, WEBAUTHN_CREDENTIAL_CURRENT_VERSION,
    WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY, WEBAUTHN_CREDENTIALS, WEBAUTHN_HASH_ALGORITHM_SHA_256,
    WEBAUTHN_USER_VERIFICATION_REQUIREMENT_DISCOURAGED,
    WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED,
};
use windows_sys::Win32::System::LibraryLoader::{
    GetProcAddress, LOAD_LIBRARY_SEARCH_SYSTEM32, LoadLibraryExW,
};
use windows_sys::Win32::UI::WindowsAndMessaging::GetForegroundWindow;
use windows_sys::core::{HRESULT, PCWSTR, w};

use super::{Assertion, Request, TOUCH_TIMEOUT};

const NTE_USER_CANCELLED: HRESULT = 0x8009_0036_u32 as HRESULT;

type GetAssertion = unsafe extern "system" fn(
    HWND,
    PCWSTR,
    *const WEBAUTHN_CLIENT_DATA,
    *const WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS,
    *mut *mut WEBAUTHN_ASSERTION,
) -> HRESULT;
/// What GetProcAddress finds.
type Proc = unsafe extern "system" fn() -> isize;
type FreeAssertion = unsafe extern "system" fn(*const WEBAUTHN_ASSERTION);
type GetErrorName = unsafe extern "system" fn(HRESULT) -> PCWSTR;

struct Api {
    get_assertion: GetAssertion,
    free_assertion: FreeAssertion,
    error_name: GetErrorName,
}

fn api() -> Option<&'static Api> {
    static API: OnceLock<Option<Api>> = OnceLock::new();
    API.get_or_init(|| {
        // SAFETY: a system DLL, by a NUL-terminated name; it stays loaded.
        let dll = unsafe {
            LoadLibraryExW(
                w!("webauthn.dll"),
                std::ptr::null_mut(),
                LOAD_LIBRARY_SEARCH_SYSTEM32,
            )
        };
        if dll.is_null() {
            return None;
        }
        // SAFETY: the functions have these signatures (webauthn.h), and
        // NUL-terminated names.
        unsafe {
            let get_assertion =
                GetProcAddress(dll, c"WebAuthNAuthenticatorGetAssertion".as_ptr().cast())?;
            let free_assertion = GetProcAddress(dll, c"WebAuthNFreeAssertion".as_ptr().cast())?;
            let error_name = GetProcAddress(dll, c"WebAuthNGetErrorName".as_ptr().cast())?;
            Some(Api {
                get_assertion: std::mem::transmute::<Proc, GetAssertion>(get_assertion),
                free_assertion: std::mem::transmute::<Proc, FreeAssertion>(free_assertion),
                error_name: std::mem::transmute::<Proc, GetErrorName>(error_name),
            })
        }
    })
    .as_ref()
}

pub fn sign(request: &Request) -> Result<Assertion, String> {
    let api = api().ok_or(
        "this Windows has no WebAuthn API (Windows 10 1903 and later have it): add the key to \
         the SSH agent and leave the key file empty",
    )?;
    // Windows always asks for the touch, and asks for the PIN itself.
    let _ = (request.user_presence, request.pin);
    let rp_id: Vec<u16> = request.application.encode_utf16().chain([0]).collect();
    // Windows hashes the client data, as OpenSSH's key expects it hashed.
    let client_data = WEBAUTHN_CLIENT_DATA {
        dwVersion: WEBAUTHN_CLIENT_DATA_CURRENT_VERSION,
        cbClientDataJSON: len(request.message)?,
        pbClientDataJSON: request.message.as_ptr().cast_mut(),
        pwszHashAlgId: WEBAUTHN_HASH_ALGORITHM_SHA_256,
    };
    let mut credential = WEBAUTHN_CREDENTIAL {
        dwVersion: WEBAUTHN_CREDENTIAL_CURRENT_VERSION,
        cbId: len(request.key_handle)?,
        pbId: request.key_handle.as_ptr().cast_mut(),
        pwszCredentialType: WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY,
    };
    let options = WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS {
        // Only the fields of version 1 are read.
        dwVersion: WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_1,
        dwTimeoutMilliseconds: TOUCH_TIMEOUT.as_millis() as u32,
        CredentialList: WEBAUTHN_CREDENTIALS {
            cCredentials: 1,
            pCredentials: &mut credential,
        },
        dwUserVerificationRequirement: if request.user_verification {
            WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED
        } else {
            WEBAUTHN_USER_VERIFICATION_REQUIREMENT_DISCOURAGED
        },
        ..Default::default()
    };
    let mut assertion: *mut WEBAUTHN_ASSERTION = std::ptr::null_mut();
    // SAFETY: the pointers point into locals that outlive the call; the
    // dialog belongs to DbCraft's window when it is in front.
    let hr = unsafe {
        (api.get_assertion)(
            GetForegroundWindow(),
            rp_id.as_ptr(),
            &client_data,
            &options,
            &mut assertion,
        )
    };
    if hr != 0 || assertion.is_null() {
        return Err(error(api, hr));
    }
    // SAFETY: Windows filled `assertion` in; it is read, then freed once.
    unsafe {
        let a = &*assertion;
        let auth_data = slice(a.pbAuthenticatorData, a.cbAuthenticatorData);
        let signature = slice(a.pbSignature, a.cbSignature).to_vec();
        let result = if auth_data.len() < 37 {
            Err("the security key's authenticator data is too short".to_owned())
        } else {
            Ok(Assertion {
                flags: auth_data[32],
                counter: u32::from_be_bytes(auth_data[33..37].try_into().expect("4 bytes")),
                signature,
            })
        };
        (api.free_assertion)(assertion);
        result
    }
}

fn len(data: &[u8]) -> Result<u32, String> {
    u32::try_from(data.len()).map_err(|_| "too much data to sign".to_owned())
}

/// # Safety
/// `data` points to `len` bytes (or is null with no bytes).
unsafe fn slice<'a>(data: *const u8, len: u32) -> &'a [u8] {
    if data.is_null() || len == 0 {
        &[]
    } else {
        // SAFETY: as the caller promises.
        unsafe { std::slice::from_raw_parts(data, len as usize) }
    }
}

fn error(api: &Api, hr: HRESULT) -> String {
    match hr {
        NTE_USER_CANCELLED => "signing with the security key was cancelled or timed out".to_owned(),
        _ => {
            // SAFETY: a static, NUL-terminated string of webauthn.dll.
            let name = unsafe {
                let name = (api.error_name)(hr);
                if name.is_null() {
                    String::new()
                } else {
                    let len = (0..).take_while(|&i| *name.add(i) != 0).count();
                    String::from_utf16_lossy(std::slice::from_raw_parts(name, len))
                }
            };
            format!("the security key didn't sign: {name} (0x{:08x})", hr as u32)
        }
    }
}
