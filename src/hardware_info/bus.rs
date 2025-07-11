//! Lightweight bus-type detector used by the auto-tuner.
//!
//! Windows  : STORAGE_QUERY_PROPERTY
//! Linux    : /sys/dev/block/…
//! macOS    : IORegistry (re-uses your existing helper)

use std::io;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bus {
    UsbBulkOnly,
    UsbUasp,
    SataAHCI,
    Nvme,
    Sas,
    Unknown,
}

#[cfg(target_os = "windows")]
pub fn detect_bus_type<P: AsRef<std::ffi::OsStr>>(path: P) -> io::Result<Bus> {
    use std::{mem, os::windows::prelude::*};
    use winapi::shared::minwindef::DWORD;
    use winapi::um::{
        fileapi::{CreateFileW, OPEN_EXISTING},
        handleapi::CloseHandle,
        ioapiset::DeviceIoControl,
        winbase::FILE_FLAG_BACKUP_SEMANTICS,
        winioctl::{
            IOCTL_STORAGE_QUERY_PROPERTY, STORAGE_DEVICE_DESCRIPTOR,
            STORAGE_PROPERTY_QUERY, StorageDeviceProperty,
        },
        winnt::{FILE_SHARE_READ, FILE_SHARE_WRITE, GENERIC_READ, GENERIC_WRITE, HANDLE},
    };

    let wide: Vec<u16> = path.as_ref().encode_wide().chain(Some(0)).collect();
    let handle: HANDLE = unsafe {
        CreateFileW(
            wide.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            std::ptr::null_mut(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            std::ptr::null_mut(),
        )
    };
    if handle.is_null() {
        return Ok(Bus::Unknown);
    }

    let mut query = STORAGE_PROPERTY_QUERY {
        PropertyId: StorageDeviceProperty,
        QueryType: 0,
        AdditionalParameters: [0; 1],
    };
    // 512 B buffer is enough for the header we need.
    let mut buf = [0u8; 512];
    let mut bytes = 0u32;
    let ok = unsafe {
        DeviceIoControl(
            handle,
            IOCTL_STORAGE_QUERY_PROPERTY,
            &mut query as *mut _ as *mut _,
            mem::size_of::<STORAGE_PROPERTY_QUERY>() as DWORD,
            buf.as_mut_ptr() as *mut _,
            buf.len() as DWORD,
            &mut bytes,
            std::ptr::null_mut(),
        )
    };
    unsafe { CloseHandle(handle) };

    if ok == 0 {
        return Ok(Bus::Unknown);
    }

    // The first byte of STORAGE_DEVICE_DESCRIPTOR after the header length
    // is *BusType* (see winioctl.h).
    let header_len = unsafe { (*(buf.as_ptr() as *const STORAGE_DEVICE_DESCRIPTOR)).HeaderSize };
    let bus_byte = buf[header_len as usize];

    let bus = match bus_byte {
        0x07 => Bus::SataAHCI,     // SATA / ATA
        0x10 => Bus::UsbBulkOnly,  // USB BOT
        0x11 => Bus::UsbUasp,      // USB UASP (sometimes 0x10 as well)
        0x17 => Bus::Nvme,
        _    => Bus::Unknown,
    };
    Ok(bus)
}

#[cfg(target_os = "linux")]
pub fn detect_bus_type<P: AsRef<std::path::Path>>(path: P) -> io::Result<Bus> {
    use std::fs;
    use std::os::unix::fs::MetadataExt;

    let md = fs::metadata(&path)?;
    let sys = format!("/sys/dev/block/{}:{}", md.rdev() >> 8, md.rdev() & 0xff);
    let link = fs::read_link(&sys)?;
    let p = link.to_string_lossy();

    if p.contains("/usb") {
        let modalias = fs::read_to_string(format!("{}/device/modalias", sys)).unwrap_or_default();
        return if modalias.contains("uas") {
            Ok(Bus::UsbUasp)
        } else {
            Ok(Bus::UsbBulkOnly)
        };
    }
    if p.contains("/nvme") { return Ok(Bus::Nvme); }
    if p.contains("/ata")  { return Ok(Bus::SataAHCI); }
    if p.contains("/sas")  { return Ok(Bus::Sas);     }
    Ok(Bus::Unknown)
}

#[cfg(target_os = "macos")]
pub fn detect_bus_type<P: AsRef<std::path::Path>>(path: P) -> io::Result<Bus> {
    // Re-use the text dump you already generate via `mac_usb_report`
    if let Ok(tree) = crate::mac_usb_report::usb_storage_summary(
        path.as_ref().to_str().unwrap_or_default()
    ) {
        if tree.contains("UAS")    { return Ok(Bus::UsbUasp);   }
        if tree.contains("USB")    { return Ok(Bus::UsbBulkOnly);}
    }
    Ok(Bus::Unknown)
}

// Fallback stub so the crate still compiles everywhere.
#[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
pub fn detect_bus_type<P, Q>(_: P) -> io::Result<Bus> { Ok(Bus::Unknown) }
