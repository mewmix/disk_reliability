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

pub type SerialResult<T> = std::result::Result<T, SerialError>;

/// Unified entry point.
pub fn disk_serial<P: AsRef<Path>>(dev: P) -> SerialResult<String> {
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
    use udev::{Device, Enumerator};

    pub fn serial<P: AsRef<Path>>(dev: P) -> SerialResult<String> {
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

    fn prop(d: &Device) -> SerialResult<String> {
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
    use winapi::shared::winerror::ERROR_INSUFFICIENT_BUFFER;
    use winapi::um::winioctl::{
        IOCTL_STORAGE_GET_DEVICE_NUMBER, IOCTL_STORAGE_QUERY_PROPERTY, STORAGE_DEVICE_NUMBER,
    };

    use winapi::um::{
        fileapi::CreateFileW,
        handleapi::CloseHandle,
        ioapiset::DeviceIoControl,
        winbase::{FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OVERLAPPED},
        winnt::{FILE_SHARE_READ, FILE_SHARE_WRITE, GENERIC_READ, HANDLE},
    };

    #[repr(C)]
    struct STORAGE_PROPERTY_QUERY {
        property_id: u32,
        query_type: u32,
        additional: [u8; 1],
    }
    const StorageDeviceProperty: u32 = 0;
    const PropertyStandardQuery: u32 = 0;

    unsafe fn physical_drive_from_letter(handle: HANDLE) -> io::Result<String> {
        let mut dev_num: STORAGE_DEVICE_NUMBER = mem::zeroed();
        let mut bytes = 0u32;
        let ok = DeviceIoControl(
            handle,
            IOCTL_STORAGE_GET_DEVICE_NUMBER,
            ptr::null_mut(),
            0,
            &mut dev_num as *mut _ as *mut _,
            mem::size_of::<STORAGE_DEVICE_NUMBER>() as u32,
            &mut bytes,
            ptr::null_mut(),
        );
        if ok == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(format!(r"\\.\PhysicalDrive{}", dev_num.DeviceNumber))
        }
    }

    fn query_serial(device_path: &str) -> SerialResult<String> {
        let wide: Vec<u16> = std::ffi::OsStr::new(device_path)
            .encode_wide()
            .chain(Some(0))
            .collect();

        unsafe {
            let handle: HANDLE = CreateFileW(
                wide.as_ptr(),
                GENERIC_READ,
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
                    let s = String::from_utf8_lossy(&buf[offset..offset + nul])
                        .trim()
                        .to_owned();
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

    pub fn serial<P: AsRef<Path>>(dev: P) -> SerialResult<String> {
        // -------- drive-letter (D:, D:\, D:/) →  \\.\D: -------------------
        let s = dev.as_ref().display().to_string();
        let mut chars = s.chars();
        let (mut device_path, is_letter) = match (chars.next(), chars.next()) {
            (Some(c), Some(':')) if c.is_ascii_alphabetic() => {
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
    use std::ffi::{CStr, CString};

    use core_foundation_sys::{
        base::{kCFAllocatorDefault, CFGetTypeID, CFRelease, CFTypeRef},
        string::{
            kCFStringEncodingUTF8, CFStringCreateWithCString, CFStringGetCString,
            CFStringGetTypeID, CFStringRef,
        },
    };
    use io_kit_sys::{
        kIOMasterPortDefault,
        ret::kIOReturnNotFound,
        types::{io_registry_entry_t, io_service_t, IO_OBJECT_NULL},
        IOBSDNameMatching, IOObjectRelease, IORegistryEntryCreateCFProperty,
        IOServiceGetMatchingService,
    };
    use mach2::port::mach_port_t;

    extern "C" {
        fn IORegistryEntryFromPath(
            master_port: mach_port_t,
            path: *const libc::c_char,
        ) -> io_registry_entry_t;
    }

    /// Safe-ish helper that replaces the missing `registry_entry_from_path`
    unsafe fn registry_entry_from_path(
        path: &str,
    ) -> std::result::Result<io_registry_entry_t, i32> {
        let c_path = CString::new(path).unwrap();
        let entry = IORegistryEntryFromPath(kIOMasterPortDefault, c_path.as_ptr());
        if entry == IO_OBJECT_NULL {
            Err(kIOReturnNotFound)
        } else {
            Ok(entry)
        }
    }

    pub fn serial<P: AsRef<Path>>(dev: P) -> SerialResult<String> {
        let bsd = dev
            .as_ref()
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or(SerialError::Other)?;

        unsafe {
            let bsd_c = CString::new(bsd).unwrap();
            let matching = IOBSDNameMatching(kIOMasterPortDefault, 0, bsd_c.as_ptr());
            if matching.is_null() {
                return Err(SerialError::Other);
            }

            let service: io_service_t = IOServiceGetMatchingService(kIOMasterPortDefault, matching);
            if service == IO_OBJECT_NULL {
                return Err(SerialError::NotFound);
            }

            let key_c = CString::new("Serial Number").unwrap();
            let key = CFStringCreateWithCString(
                kCFAllocatorDefault,
                key_c.as_ptr(),
                kCFStringEncodingUTF8,
            );
            if key.is_null() {
                IOObjectRelease(service);
                return Err(SerialError::Other);
            }

            let value = IORegistryEntryCreateCFProperty(service, key, kCFAllocatorDefault, 0);
            CFRelease(key as CFTypeRef);
            IOObjectRelease(service);
            if value.is_null() {
                return Err(SerialError::NotFound);
            }

            if CFGetTypeID(value) != CFStringGetTypeID() {
                CFRelease(value);
                return Err(SerialError::Other);
            }

            let cf_str: CFStringRef = value as CFStringRef;
            let mut buf = vec![0i8; 256];
            let ok = CFStringGetCString(
                cf_str,
                buf.as_mut_ptr(),
                buf.len() as _,
                kCFStringEncodingUTF8,
            );
            CFRelease(value);
            if ok == 0 {
                return Err(SerialError::Other);
            }
            let cstr = CStr::from_ptr(buf.as_ptr());
            let serial = cstr.to_string_lossy().into_owned();
            if serial.is_empty() {
                Err(SerialError::NotFound)
            } else {
                Ok(serial)
            }
        }
    }
}
