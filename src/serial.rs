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
    use core::ffi::c_void;
    use windows_sys::Win32::{
        Foundation::{CloseHandle, ERROR_INSUFFICIENT_BUFFER, GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE},
        Storage::FileSystem::{
            CreateFileW, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OVERLAPPED, FILE_SHARE_READ, FILE_SHARE_WRITE,
        },
        System::IO::DeviceIoControl,
        System::Ioctl::{
            IOCTL_STORAGE_GET_DEVICE_NUMBER, STORAGE_DEVICE_NUMBER,
            IOCTL_STORAGE_QUERY_PROPERTY, STORAGE_PROPERTY_QUERY, STORAGE_DEVICE_DESCRIPTOR,
            StorageDeviceProperty, PropertyStandardQuery,
        },
            if handle == INVALID_HANDLE_VALUE {
                PropertyId: StorageDeviceProperty,
                QueryType: PropertyStandardQuery,
                AdditionalParameters: [0],
            if h == INVALID_HANDLE_VALUE {
            Err(io::Error::last_os_error())
        } else {
            Ok(format!(r"\\.\PhysicalDrive{}", dev_num.DeviceNumber))
        }
    }

    fn query_serial(device_path: &str) -> Result<String> {
        let wide: Vec<u16> = std::ffi::OsStr::new(device_path)
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
            let result = if ok == 0 {
                let err = io::Error::last_os_error();
                if err.raw_os_error() == Some(ERROR_INSUFFICIENT_BUFFER as i32) {
                    Err(SerialError::Other)
                } else {
                    Err(SerialError::Io(err))
                }
            } else {
                let desc: &STORAGE_DEVICE_DESCRIPTOR = &*(buf.as_ptr() as *const _);
                if desc.serial_number_offset == 0 {
                    Err(SerialError::NotFound)
                } else {
                    let offset = desc.serial_number_offset as usize;
                    let nul = buf[offset..].iter().position(|&b| b == 0).unwrap_or(0);
                    let s = String::from_utf8_lossy(&buf[offset..offset + nul]).trim().to_owned();
                    if s.is_empty() {
                        Err(SerialError::NotFound)
                    } else {
                        Ok(s)
                    }
                }
            };
            CloseHandle(handle);
            result
        }
    }

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
        // -------- drive-letter (D:, D:\, D:/) →  \\.\D: -------------------
        let s = dev.as_ref().display().to_string();
        let (mut device_path, is_letter) = match s.chars().next() {
            Some(c) if c.is_ascii_alphabetic()
                && (s.len() == 2 || s.starts_with(":\\") || s.starts_with(":/")) =>
            {
                (format!(r"\\.\{}:", c.to_ascii_uppercase()), true)
            }
            _ => (s, false),
        };

        let wide: Vec<u16> = std::ffi::OsStr::new(&device_path)
            .encode_wide()
            .chain(Some(0))
            .collect();

        unsafe {
            let h = CreateFileW(
                wide.as_ptr(),
                0,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                ptr::null_mut(),
                3, // OPEN_EXISTING
                FILE_FLAG_BACKUP_SEMANTICS,
                ptr::null_mut(),
            );
            if h.is_null() {
                return Err(io::Error::last_os_error().into());
            }

            if is_letter {
                device_path = physical_drive_from_letter(h)?;
            }
            CloseHandle(h);
        }

        query_serial(&device_path)
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
