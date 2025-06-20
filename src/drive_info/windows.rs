#![allow(non_snake_case)]
use std::{ffi::OsStr, io, mem, os::windows::prelude::*, ptr};
use winapi::shared::{
    ntdef::HANDLE,
    winerror::ERROR_INSUFFICIENT_BUFFER,
    minwindef::DWORD,
    winioctl::{
        IOCTL_STORAGE_QUERY_PROPERTY, IOCTL_STORAGE_GET_DEVICE_NUMBER,
        STORAGE_PROPERTY_QUERY, STORAGE_DESCRIPTOR_HEADER,
        STORAGE_DEVICE_DESCRIPTOR, STORAGE_QUERY_TYPE,
        STORAGE_PROPERTY_ID, StorageDeviceProperty,
        StorageDeviceProtocolSpecificProperty,
        STORAGE_PROTOCOL_TYPE, ProtocolTypeNvme,
        STORAGE_PROTOCOL_DATA_TYPE, NVMeDataTypeLogPage,
        STORAGE_PROTOCOL_SPECIFIC_DATA,
    },
};
use winapi::um::{
    fileapi::CreateFileW,
    winbase::FILE_FLAG_BACKUP_SEMANTICS,
    handleapi::CloseHandle,
    winnt::{FILE_SHARE_READ, FILE_SHARE_WRITE, GENERIC_READ, GENERIC_WRITE},
    ioapiset::DeviceIoControl,
};

const LOGPAGE_SMART: DWORD = 0x02;
const NVME_SMART_LOG_LEN: usize = 512;

/* ---------- Safe wrappers ------------------------------------------------ */

pub struct DeviceDescriptor {
    pub model:       String,
    pub firmware:    String,
    pub serial:      String,
    pub bus_type:    u8, // 0x17 == NVMe
}

pub struct NvmeSmart {
    pub critical_warning:      u8,
    pub temperature_C:         u16,
    pub avail_spare_pct:       u8,
    pub used_pct:              u8,
    pub data_units_read:       u128, // 1000 * 512-byte units
    pub data_units_written:    u128,
    pub host_reads:            u128,
    pub host_writes:           u128,
    pub power_cycles:          u64,
    pub power_on_hours:        u64,
    pub unsafe_shutdowns:      u64,
    pub media_errors:          u64,
    pub num_err_log_entries:   u64,
}

pub fn query_drive<P: AsRef<OsStr>>(path: P) -> io::Result<(DeviceDescriptor, NvmeSmart)> {
    let vol = canonical_volume_path(path.as_ref())?;
    unsafe {
        let h = open_handle(&vol)?;
        let phys = physical_drive_from_volume(h)?;
        CloseHandle(h);

        let h = open_handle(&phys)?;
        let desc  = device_descriptor(h)?;
        let smart = nvme_smart_page(h)?;
        CloseHandle(h);

        Ok((desc, smart))
    }
}

/* ---------- Implementation details -------------------------------------- */

unsafe fn open_handle(p: &str) -> io::Result<HANDLE> {
    let wide: Vec<u16> = OsStr::new(p).encode_wide().chain(Some(0)).collect();
    let h = CreateFileW(
        wide.as_ptr(),
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        ptr::null_mut(),
        3, // OPEN_EXISTING
        FILE_FLAG_BACKUP_SEMANTICS,
        ptr::null_mut(),
    );
    if h.is_null() { Err(io::Error::last_os_error()) } else { Ok(h) }
}

fn canonical_volume_path(s: &OsStr) -> io::Result<String> {
    let s = s.to_string_lossy();
    if let Some(c) = s.chars().next()
          .filter(|c| c.is_ascii_alphabetic())
          .filter(|_| s.len()==2 || s.starts_with(":\\") || s.starts_with(":/")) {
        Ok(format!(r"\\.\{}:", c.to_ascii_uppercase()))
    } else { Ok(s.into_owned()) }
}

/// volume HANDLE → \\.\PhysicalDriveN
unsafe fn physical_drive_from_volume(h: HANDLE) -> io::Result<String> {
    use winapi::shared::winioctl::STORAGE_DEVICE_NUMBER;
    let mut num: STORAGE_DEVICE_NUMBER = mem::zeroed();
    let mut bytes = 0u32;
    let ok = DeviceIoControl(
        h,
        IOCTL_STORAGE_GET_DEVICE_NUMBER,
        ptr::null_mut(), 0,
        &mut num as *mut _ as *mut _, mem::size_of::<STORAGE_DEVICE_NUMBER>() as u32,
        &mut bytes,
        ptr::null_mut(),
    );
    if ok == 0 { return Err(io::Error::last_os_error()); }
    Ok(format!(r"\\.\PhysicalDrive{}", num.DeviceNumber))
}

unsafe fn device_descriptor(h: HANDLE) -> io::Result<DeviceDescriptor> {
    let query = STORAGE_PROPERTY_QUERY {
        PropertyId: StorageDeviceProperty as STORAGE_PROPERTY_ID,
        QueryType:  0 as STORAGE_QUERY_TYPE, // standard
        AdditionalParameters: [0],
    };
    // first, header
    let mut hdr: STORAGE_DESCRIPTOR_HEADER = mem::zeroed();
    let mut bytes = 0u32;
    DeviceIoControl(
        h, IOCTL_STORAGE_QUERY_PROPERTY,
        &query as *const _ as *mut _, mem::size_of::<STORAGE_PROPERTY_QUERY>() as u32,
        &mut hdr as *mut _ as *mut _, mem::size_of::<STORAGE_DESCRIPTOR_HEADER>() as u32,
        &mut bytes, ptr::null_mut(),
    );
    let mut buf = vec![0u8; hdr.Size as usize];
    DeviceIoControl(
        h, IOCTL_STORAGE_QUERY_PROPERTY,
        &query as *const _ as *mut _, mem::size_of::<STORAGE_PROPERTY_QUERY>() as u32,
        buf.as_mut_ptr() as *mut _, buf.len() as u32,
        &mut bytes, ptr::null_mut(),
    );
    let desc: &STORAGE_DEVICE_DESCRIPTOR = &*(buf.as_ptr() as *const _);

    let str_at = |ofs: u32| -> String {
        if ofs == 0 { return String::new(); }
        let p = &buf[ofs as usize..];
        let len = p.iter().position(|&b| b==0).unwrap_or(0);
        String::from_utf8_lossy(&p[..len]).trim().to_owned()
    };
    Ok(DeviceDescriptor {
        model:    str_at(desc.ProductIdOffset),
        firmware: str_at(desc.ProductRevisionOffset),
        serial:   str_at(desc.SerialNumberOffset),
        bus_type: desc.BusType,
    })
}

unsafe fn nvme_smart_page(h: HANDLE) -> io::Result<NvmeSmart> {
    #[repr(C)] struct QUERY {
        hdr: STORAGE_PROPERTY_QUERY,
        spec: STORAGE_PROTOCOL_SPECIFIC_DATA,
        buf:  [u8; NVME_SMART_LOG_LEN],
    }
    let mut q: QUERY = mem::zeroed();
    q.hdr.PropertyId = StorageDeviceProtocolSpecificProperty as STORAGE_PROPERTY_ID;
    q.hdr.QueryType  = 0; // standard
    q.spec.ProtocolType  = ProtocolTypeNvme as STORAGE_PROTOCOL_TYPE;
    q.spec.DataType      = NVMeDataTypeLogPage as STORAGE_PROTOCOL_DATA_TYPE;
    q.spec.ProtocolDataRequestValue = LOGPAGE_SMART;
    q.spec.ProtocolDataOffset = mem::size_of::<STORAGE_PROTOCOL_SPECIFIC_DATA>() as DWORD;
    q.spec.ProtocolDataLength = NVME_SMART_LOG_LEN as DWORD;

    let mut bytes = 0u32;
    let ok = DeviceIoControl(
        h,
        IOCTL_STORAGE_QUERY_PROPERTY,
        &mut q as *mut _ as *mut _, mem::size_of::<QUERY>() as u32,
        &mut q as *mut _ as *mut _, mem::size_of::<QUERY>() as u32,
        &mut bytes,
        ptr::null_mut(),
    );
    if ok == 0 {
        let e = io::Error::last_os_error();
        if e.raw_os_error()==Some(ERROR_INSUFFICIENT_BUFFER as i32) {
            return Err(io::Error::new(io::ErrorKind::Other,"SMART page too small"));
        }
        return Err(e);
    }
    parse_smart(&q.buf)
}

fn le_u16(b:&[u8]) -> u16 { u16::from_le_bytes([b[0],b[1]]) }
fn le_u64(b:&[u8]) -> u64 { u64::from_le_bytes(b[0..8].try_into().unwrap()) }
fn le_u128(b:&[u8]) -> u128 { u128::from_le_bytes(b[0..16].try_into().unwrap()) }

fn parse_smart(buf:&[u8]) -> io::Result<NvmeSmart> {
    if buf.len()<512 { return Err(io::Error::new(io::ErrorKind::UnexpectedEof,"smart log")); }
    Ok(NvmeSmart{
        critical_warning:    buf[0],
        temperature_C:       le_u16(&buf[1..3]) - 273,
        avail_spare_pct:     buf[3],
        used_pct:            buf[5],
        data_units_read:     le_u128(&buf[32..48]),
        data_units_written:  le_u128(&buf[48..64]),
        host_reads:          le_u128(&buf[64..80]),
        host_writes:         le_u128(&buf[80..96]),
        power_cycles:        le_u64(&buf[100..108]),
        power_on_hours:      le_u64(&buf[108..116]),
        unsafe_shutdowns:    le_u64(&buf[116..124]),
        media_errors:        le_u64(&buf[124..132]),
        num_err_log_entries: le_u64(&buf[132..140]),
    })
}
