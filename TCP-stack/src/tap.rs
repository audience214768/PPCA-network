//! TAP device — open, configure, read/write raw Ethernet frames.
//!
//! Uses Linux `/dev/net/tun` with `IFF_TAP | IFF_NO_PI` so each read/write
//! is a complete Ethernet frame (no packet-info header).

use std::fs;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::io::IntoRawFd;

const TUNSETIFF: libc::c_ulong = 0x4004_54CA;
const IFF_TAP: libc::c_short = 0x0002;
const IFF_NO_PI: libc::c_short = 0x1000;

pub struct TapDevice {
    fd: OwnedFd,
    pub name: String,
    pub mac: [u8; 6],
}

impl TapDevice {
    pub fn open(name: &str) -> io::Result<Self> {
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/net/tun")?;

        // struct ifreq: 16B name + 2B flags + 22B padding = 40B
        let mut ifreq = [0u8; 40];
        let name_bytes = name.as_bytes();
        ifreq[..name_bytes.len()].copy_from_slice(name_bytes);
        let flags: i16 = (IFF_TAP | IFF_NO_PI) as i16;
        ifreq[16..18].copy_from_slice(&flags.to_ne_bytes());

        let tmp_fd = file.as_raw_fd();
        let ret = unsafe { libc::ioctl(tmp_fd, TUNSETIFF, ifreq.as_mut_ptr() as *mut libc::c_void) };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        let raw = file.into_raw_fd();
        let owned = unsafe { OwnedFd::from_raw_fd(raw) };

        let mac = Self::read_mac(name).unwrap();

        Ok(Self {
            fd: owned,
            name: name.to_string(),
            mac,
        })
    }

    /// Read one Ethernet frame. Returns number of bytes read.
    pub fn read_frame(&self, buf: &mut [u8]) -> io::Result<usize> {
        let ret = unsafe {
            libc::read(
                self.fd.as_raw_fd(),
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
            )
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(ret as usize)
    }

    /// Write one Ethernet frame.
    pub fn write_frame(&self, data: &[u8]) -> io::Result<()> {
        let ret = unsafe {
            libc::write(
                self.fd.as_raw_fd(),
                data.as_ptr() as *const libc::c_void,
                data.len(),
            )
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn read_mac(name: &str) -> Option<[u8; 6]> {
        let path = format!("/sys/class/net/{}/address", name);
        let s = fs::read_to_string(path).ok()?;
        let s = s.trim();
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 6 {
            return None;
        }
        let mut mac = [0u8; 6];
        for (i, p) in parts.iter().enumerate() {
            mac[i] = u8::from_str_radix(p, 16).ok()?;
        }
        Some(mac)
    }
}
