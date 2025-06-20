use std::{io, path::Path};

#[derive(Debug, thiserror::Error)]
pub enum SerialError {
    #[error("device not found")]
    NotFound,
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("unexpected")]
    Other,
}

pub type Result<T> = std::result::Result<T, SerialError>;

/// Unified entry point.
pub fn disk_serial<P: AsRef<Path>>(dev: P) -> Result<String> {
    cfg_if::cfg_if! {
        if #[cfg(target_os = "linux")] {
            linux::serial(dev)
        } else if #[cfg(target_os = "windows")] {
            windows::serial(dev)
        } else if #[cfg(target_os = "macos")] {
            macos::serial(dev)
        } else {
            Err(SerialError::Other)
        }
    }
}

/* ---------- LINUX ---------- */
#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use udev::{Enumerator, Device};

    pub fn serial<P: AsRef<Path>>(dev: P) -> Result<String> {
        let dev = dev.as_ref().canonicalize()?;
        // Map /dev/whatever to its sysfs device and read SERIAL property.
        let mut en = Enumerator::new()?;
        en.match_subsystem("block")?;
        for d in en.scan_devices()? {
            if let Some(node) = d.devnode() {
                if node == dev {
                    return prop(&d);
                }
            }
        }
        Err(SerialError::NotFound)
    }

    fn prop(d: &Device) -> Result<String> {
        d.property_value("ID_SERIAL_SHORT")
            .or_else(|| d.property_value("ID_SERIAL"))
            .map(|v| v.to_string_lossy().into_owned())
            .ok_or(SerialError::NotFound)
    }
}

/* ---------- WINDOWS ---------- */
#[cfg(target_os = "windows")]
mod windows {
    use super::*;
    use std::{mem, os::windows::prelude::*, ptr};
    use winapi::ctypes::c_void;
    use winapi::um::{
        fileapi::CreateFileW,
        winbase::{FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OVERLAPPED},
        winnt::{FILE_SHARE_READ, FILE_SHARE_WRITE, GENERIC_READ, GENERIC_WRITE, HANDLE},
        ioapiset::DeviceIoControl,
    };
    use winapi::shared::winerror::ERROR_INSUFFICIENT_BUFFER;

    #[repr(C)]
    struct STORAGE_PROPERTY_QUERY {
        property_id: u32,
        query_type: u32,
        additional: [u8; 1],
    }
    const StorageDeviceProperty: u32 = 0;
    const PropertyStandardQuery: u32 = 0;
    const IOCTL_STORAGE_QUERY_PROPERTY: u32 = 0x2D1400;

    #[repr(C)]
    struct STORAGE_DEVICE_DESCRIPTOR {
        version: u32,
        size: u32,
        device_type: u8,
        device_type_modifier: u8,
        removable_media: u8,
        command_queueing: u8,
        vendor_id_offset: u32,
        product_id_offset: u32,
        product_revision_offset: u32,
        serial_number_offset: u32,
        bus_type: u8,
        raw_properties_length: u32,
        // followed by raw data
    }

    pub fn serial<P: AsRef<Path>>(dev: P) -> Result<String> {
        let wide: Vec<u16> = dev
            .as_ref()
            .as_os_str()
            .encode_wide()
            .chain(Some(0))
            .collect();

        unsafe {
            let handle: HANDLE = CreateFileW(
                wide.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                ptr::null_mut(),
                3, // OPEN_EXISTING
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
                ptr::null_mut(),
            );
            if handle.is_null() {
                return Err(io::Error::last_os_error().into());
            }

            let query = STORAGE_PROPERTY_QUERY {
                property_id: StorageDeviceProperty,
                query_type: PropertyStandardQuery,
                additional: [0],
            };

            let mut buf = vec![0u8; 1024];
            let mut bytes = 0u32;
            let ok = DeviceIoControl(
                handle,
                IOCTL_STORAGE_QUERY_PROPERTY,
                &query as *const _ as *mut c_void,
                mem::size_of::<STORAGE_PROPERTY_QUERY>() as u32,
                buf.as_mut_ptr() as *mut c_void,
                buf.len() as u32,
                &mut bytes,
                ptr::null_mut(),
            );
            if ok == 0 {
                let err = io::Error::last_os_error();
                if err.raw_os_error() == Some(ERROR_INSUFFICIENT_BUFFER as i32) {
                    return Err(SerialError::Other);
                }
                return Err(err.into());
            }

            let desc: &STORAGE_DEVICE_DESCRIPTOR = &*(buf.as_ptr() as *const _);
            if desc.serial_number_offset == 0 {
                return Err(SerialError::NotFound);
            }
            let offset = desc.serial_number_offset as usize;
            let nul = buf[offset..].iter().position(|&b| b == 0).unwrap_or(0);
            let s = String::from_utf8_lossy(&buf[offset..offset + nul]).trim().to_owned();
            if s.is_empty() {
                Err(SerialError::NotFound)
            } else {
                Ok(s)
            }
        }
    }
}

/* ---------- macOS ---------- */
#[cfg(target_os = "macos")]
mod macos {
    use super::*;
    use ioreg::{self, IOReturn};

    pub fn serial<P: AsRef<Path>>(dev: P) -> Result<String> {
        // Match IOMedia objects with BSD Name == disk* and fetch "Serial Number"
        let bsd = dev
            .as_ref()
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or(SerialError::Other)?;

        let root = ioreg::registry_entry_from_path("IOService:/")?;
        for media in root
            .iterate("IOMedia")
            .map_err(|_| SerialError::Other)?
        {
            let name: String = media.property("BSD Name").unwrap_or_default();
            if name == bsd {
                let sn: String = media.property("Serial Number").unwrap_or_default();
                return if sn.is_empty() {
                    Err(SerialError::NotFound)
                } else {
                    Ok(sn)
                };
            }
        }
        Err(SerialError::NotFound)
    }
}
