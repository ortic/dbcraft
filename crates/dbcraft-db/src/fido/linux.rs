//! FIDO devices on Linux: the `hidraw` devices whose report descriptor has
//! the FIDO usage page. systemd's udev rules give the logged-in user access
//! to them.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::time::Duration;

use super::ctap::{Device, REPORT};

const FIDO_USAGE_PAGE: u32 = 0xf1d0;

pub struct Hidraw {
    file: File,
}

/// The FIDO devices that can be opened.
pub fn devices() -> Result<Vec<Hidraw>, String> {
    let mut devices = Vec::new();
    let mut denied = Vec::new();
    let Ok(entries) = fs::read_dir("/sys/class/hidraw") else {
        return Ok(devices);
    };
    for entry in entries.flatten() {
        let descriptor = entry.path().join("device/report_descriptor");
        if !fs::read(&descriptor).is_ok_and(|d| is_fido(&d)) {
            continue;
        }
        let path = PathBuf::from("/dev").join(entry.file_name());
        match OpenOptions::new().read(true).write(true).open(&path) {
            Ok(file) => devices.push(Hidraw { file }),
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => denied.push(path),
            Err(e) => tracing::warn!("opening {}: {e}", path.display()),
        }
    }
    if devices.is_empty()
        && let Some(path) = denied.first()
    {
        return Err(format!(
            "no access to the security key {}: it needs a udev rule that lets you use it \
             (as systemd's or libfido2's)",
            path.display()
        ));
    }
    Ok(devices)
}

/// Whether a HID report descriptor's usage page is FIDO's.
fn is_fido(descriptor: &[u8]) -> bool {
    let mut at = 0;
    while let Some(&prefix) = descriptor.get(at) {
        if prefix == 0xfe {
            // A long item: its size is in the next byte.
            let size = descriptor.get(at + 1).copied().unwrap_or(0);
            at += 3 + usize::from(size);
            continue;
        }
        let size = [0, 1, 2, 4][usize::from(prefix & 0x03)];
        let Some(data) = descriptor.get(at + 1..at + 1 + size) else {
            return false;
        };
        // Usage Page, a global item.
        if prefix & 0xfc == 0x04 {
            let page = data
                .iter()
                .rev()
                .fold(0u32, |page, byte| (page << 8) | u32::from(*byte));
            if page == FIDO_USAGE_PAGE {
                return true;
            }
        }
        at += 1 + size;
    }
    false
}

impl Device for Hidraw {
    fn write(&mut self, report: &[u8; REPORT]) -> io::Result<()> {
        // Report ID 0 first: FIDO devices have no numbered reports.
        let mut buf = [0; REPORT + 1];
        buf[1..].copy_from_slice(report);
        self.file.write_all(&buf)
    }

    fn read(&mut self, timeout: Duration) -> io::Result<Option<[u8; REPORT]>> {
        let mut fd = libc::pollfd {
            fd: self.file.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let ms = i32::try_from(timeout.as_millis()).unwrap_or(i32::MAX);
        // SAFETY: one valid pollfd for the duration of the call.
        match unsafe { libc::poll(&mut fd, 1, ms) } {
            0 => return Ok(None),
            n if n < 0 => {
                let e = io::Error::last_os_error();
                return if e.kind() == io::ErrorKind::Interrupted {
                    Ok(None)
                } else {
                    Err(e)
                };
            }
            _ => {}
        }
        let mut report = [0; REPORT];
        let n = self.file.read(&mut report)?;
        if n != REPORT {
            return Err(io::Error::other(format!("a HID report of {n} bytes")));
        }
        Ok(Some(report))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fido_descriptors() {
        // A FIDO interface: usage page 0xF1D0, 64-byte input and output reports.
        let yubikey = [
            0x06, 0xd0, 0xf1, 0x09, 0x01, 0xa1, 0x01, 0x09, 0x20, 0x15, 0x00, 0x26, 0xff, 0x00,
            0x75, 0x08, 0x95, 0x40, 0x81, 0x02, 0x09, 0x21, 0x15, 0x00, 0x26, 0xff, 0x00, 0x75,
            0x08, 0x95, 0x40, 0x91, 0x02, 0xc0,
        ];
        assert!(is_fido(&yubikey));
        // A keyboard.
        let keyboard = [0x05, 0x01, 0x09, 0x06, 0xa1, 0x01, 0x05, 0x07, 0xc0];
        assert!(!is_fido(&keyboard));
        assert!(!is_fido(&[0x06, 0xd0]));
        assert!(!is_fido(&[]));
    }
}
