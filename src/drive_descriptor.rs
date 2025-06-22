#[derive(Debug, Clone, Copy)]
pub enum BusType {
    Usb,
    Nvme,
    Sata,
    Sas,
    Sd,
    Thunderbolt,
    Unknown,
}

impl Default for BusType {
    fn default() -> Self {
        BusType::Unknown
    }
}

#[derive(Debug, Clone, Copy)]
pub enum MediaKind {
    Ssd,
    Hdd,
    Optical,
    FlashRemovable,
    Unknown,
}

impl Default for MediaKind {
    fn default() -> Self {
        MediaKind::Unknown
    }
}

#[derive(Debug, Default)]
pub struct DriveDescriptor {
    pub bus: BusType,
    pub media: MediaKind,
    pub rotational: Option<bool>,
    pub sector_size: Option<u32>,
}

pub fn drive_descriptor_from_path(p: &str) -> std::io::Result<DriveDescriptor> {
    #[cfg(target_os = "linux")]
    {
        return linux_descriptor(p);
    }
    #[cfg(target_os = "macos")]
    {
        return mac_descriptor(p);
    }
    #[cfg(target_os = "windows")]
    {
        return win_descriptor(p);
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::Other,
        "OS-unsupported",
    ))
}

#[cfg(target_os = "linux")]
fn linux_descriptor(p: &str) -> std::io::Result<DriveDescriptor> {
    use std::{fs, io, path::Path};

    let path = crate::path_utils::canonical_block(p)?;
    let dev = fs::canonicalize(&path)?;
    let name = dev
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "invalid device"))?;

    let sys_path = Path::new("/sys/block").join(name);

    let rotational = fs::read_to_string(sys_path.join("queue/rotational"))
        .ok()
        .and_then(|v| v.trim().parse::<u32>().ok())
        .map(|v| v != 0);

    let sector_size = fs::read_to_string(sys_path.join("queue/logical_block_size"))
        .ok()
        .and_then(|v| v.trim().parse::<u32>().ok());

    let bus = fs::read_link(sys_path.join("device/subsystem"))
        .ok()
        .and_then(|l| {
            l.file_name().and_then(|s| s.to_str()).map(|s| match s {
                "nvme" => BusType::Nvme,
                "usb" => BusType::Usb,
                "mmc" => BusType::Sd,
                "sas" => BusType::Sas,
                "scsi" => BusType::Sata,
                _ => BusType::Unknown,
            })
        })
        .unwrap_or(BusType::Unknown);

    let media = match rotational {
        Some(true) => MediaKind::Hdd,
        Some(false) => MediaKind::Ssd,
        None => MediaKind::Unknown,
    };

    Ok(DriveDescriptor {
        bus,
        media,
        rotational,
        sector_size,
    })
}

#[cfg(target_os = "macos")]
fn mac_descriptor(p: &str) -> std::io::Result<DriveDescriptor> {
    use plist::Value;
    use std::{io, process::Command};

    let path = crate::path_utils::canonical_block(p)?;

    let out = Command::new("diskutil")
        .arg("info")
        .arg("-plist")
        .arg(&path)
        .output()?;

    let plist = Value::from_reader_xml(&*out.stdout)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    let dict = plist
        .as_dictionary()
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "unexpected output"))?;

    let bus = dict
        .get("Protocol")
        .or_else(|| dict.get("BusProtocol"))
        .and_then(|v| v.as_string())
        .map(|s| match s.to_ascii_lowercase().as_str() {
            "usb" => BusType::Usb,
            "nvme" | "pci-express" => BusType::Nvme,
            "sata" => BusType::Sata,
            "sas" => BusType::Sas,
            "sd" | "mmc" => BusType::Sd,
            "thunderbolt" => BusType::Thunderbolt,
            _ => BusType::Unknown,
        })
        .unwrap_or(BusType::Unknown);

    let rotational = dict
        .get("SolidState")
        .and_then(|v| v.as_boolean())
        .map(|solid| !solid);

    let sector_size = dict
        .get("DeviceBlockSize")
        .and_then(|v| v.as_signed_integer())
        .map(|n| n as u32);

    let media = if rotational == Some(true) {
        MediaKind::Hdd
    } else {
        MediaKind::Ssd
    };

    Ok(DriveDescriptor {
        bus,
        media,
        rotational,
        sector_size,
    })
}

#[cfg(target_os = "windows")]
fn win_descriptor(p: &str) -> std::io::Result<DriveDescriptor> {
    use std::{io, mem, os::windows::prelude::*, ptr};
    use winapi::um::{
        fileapi::CreateFileW,
        handleapi::CloseHandle,
        ioapiset::DeviceIoControl,
        winbase::FILE_FLAG_BACKUP_SEMANTICS,
        winioctl::{DISK_GEOMETRY, IOCTL_DISK_GET_DRIVE_GEOMETRY},
        winnt::{FILE_SHARE_READ, FILE_SHARE_WRITE, GENERIC_READ, GENERIC_WRITE},
    };

    let path = crate::path_utils::canonical_block(p)?;

    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    if !wide.last().map(|w| *w == 0).unwrap_or(false) {
        wide.push(0);
    }

    unsafe {
        let handle = CreateFileW(
            wide.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            ptr::null_mut(),
            3, // OPEN_EXISTING
            FILE_FLAG_BACKUP_SEMANTICS,
            ptr::null_mut(),
        );
        if handle.is_null() {
            return Err(io::Error::last_os_error());
        }

        let mut geom: DISK_GEOMETRY = mem::zeroed();
        let mut bytes = 0u32;
        let ok = DeviceIoControl(
            handle,
            IOCTL_DISK_GET_DRIVE_GEOMETRY,
            ptr::null_mut(),
            0,
            &mut geom as *mut _ as *mut _,
            mem::size_of::<DISK_GEOMETRY>() as u32,
            &mut bytes,
            ptr::null_mut(),
        );
        CloseHandle(handle);
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }

        let rotational = match geom.MediaType {
            12 | 13 => Some(false), // FixedMedia or SSD
            _ => Some(true),
        };

        let sector_size = Some(geom.BytesPerSector as u32);

        Ok(DriveDescriptor {
            bus: BusType::Unknown,
            media: if rotational == Some(true) {
                MediaKind::Hdd
            } else {
                MediaKind::Ssd
            },
            rotational,
            sector_size,
        })
    }
}
