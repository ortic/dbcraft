//! FIDO devices on macOS, through IOKit's HID manager (by hidapi).

use std::io;
use std::time::Duration;

use hidapi::{HidApi, HidDevice};

use super::ctap::{Device, REPORT};

const FIDO_USAGE_PAGE: u16 = 0xf1d0;
const FIDO_USAGE: u16 = 0x01;

pub struct Hid {
    device: HidDevice,
}

pub fn devices() -> Result<Vec<Hid>, String> {
    let api = HidApi::new().map_err(|e| format!("listing the USB devices: {e}"))?;
    let mut devices = Vec::new();
    for info in api.device_list() {
        if info.usage_page() != FIDO_USAGE_PAGE || info.usage() != FIDO_USAGE {
            continue;
        }
        match info.open_device(&api) {
            Ok(device) => devices.push(Hid { device }),
            Err(e) => tracing::warn!("opening the security key {:?}: {e}", info.path()),
        }
    }
    Ok(devices)
}

impl Device for Hid {
    fn write(&mut self, report: &[u8; REPORT]) -> io::Result<()> {
        // Report ID 0 first, as hidapi wants it for unnumbered reports.
        let mut buf = [0; REPORT + 1];
        buf[1..].copy_from_slice(report);
        self.device.write(&buf).map_err(io::Error::other)?;
        Ok(())
    }

    fn read(&mut self, timeout: Duration) -> io::Result<Option<[u8; REPORT]>> {
        let mut report = [0; REPORT];
        let ms = i32::try_from(timeout.as_millis()).unwrap_or(i32::MAX);
        match self.device.read_timeout(&mut report, ms) {
            Ok(0) => Ok(None),
            Ok(n) if n == REPORT => Ok(Some(report)),
            Ok(n) => Err(io::Error::other(format!("a HID report of {n} bytes"))),
            Err(e) => Err(io::Error::other(e)),
        }
    }
}
