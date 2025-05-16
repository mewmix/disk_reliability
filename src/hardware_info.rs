use sysinfo::{Disk, System};
use sysinfo::traits::{DiskExt, SystemExt};
use sysinfo::RefreshKind;
use std::io;
use std::process::Command;
use std::collections::HashMap;

/// Retrieves information about the disk at the given path.
pub fn get_disk_info(disk_path: &str) -> io::Result<String> {
    let refresh_kind = RefreshKind::new().with_disks();
    let mut sys = System::new_with_specifics(refresh_kind);

    for disk in sys.disks() {
        let mount_point = disk.mount_point().to_string_lossy();
        if mount_point.starts_with(disk_path) {
            return Ok(format!(
                "Disk: {}\nType: {:?}\nTotal Space: {:.2} GB\nAvailable: {:.2} GB",
                mount_point,
                disk.kind(),
                disk.total_space() as f64 / (1024.0 * 1024.0 * 1024.0),
                disk.available_space() as f64 / (1024.0 * 1024.0 * 1024.0)
            ));
        }
    }

    Err(io::Error::new(io::ErrorKind::NotFound, "Disk not found"))
}

/// Get the block size for a given disk path (OS-specific)
#[cfg(target_os = "windows")]
pub fn get_block_size_windows(disk_path: &str) -> io::Result<u64> {
    let output = Command::new("fsutil")
        .args(["fsinfo", "ntfsinfo", disk_path])
        .output()?;

    let output_str = String::from_utf8_lossy(&output.stdout);
    for line in output_str.lines() {
        if line.contains("Bytes Per Sector") {
            let parts: Vec<&str> = line.split(':').collect();
            if let Some(size_str) = parts.get(1) {
                return size_str
                    .trim()
                    .parse::<u64>()
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e));
            }
        }
    }

    Err(io::Error::new(io::ErrorKind::NotFound, "Block size not found"))
}

/// Retrieves USB controller and vendor info for the disk on Windows.
#[cfg(target_os = "windows")]
pub fn get_usb_controller_info_windows(disk_path: &str) -> io::Result<String> {
    let output = Command::new("powershell")
        .args([
            "-Command",
            "Get-PnpDevice | Where-Object { $_.Class -eq 'USB' } | Format-List Name,DeviceID",
        ])
        .output()?;

    let result = String::from_utf8_lossy(&output.stdout);
    let lines: Vec<&str> = result.split('\n').collect();

    let mut device_map = HashMap::new();
    let mut current_name = String::new();

    for line in lines {
        if line.contains("Name") {
            current_name = line.replace("Name :", "").trim().to_string();
        } else if line.contains("DeviceID") {
            let device_id = line.replace("DeviceID :", "").trim().to_string();
            device_map.insert(device_id, current_name.clone());
        }
    }

    // Adjust this to match your disk path to DeviceID mapping
    // For example, disk_path might be "C:\\" or similar
    let disk_device = format!("\\\\.\\{}", disk_path.trim_end_matches(":"));

    for (id, name) in device_map {
        if id.contains(&disk_device) {
            return Ok(format!("USB Controller: {}\nDevice ID: {}", name, id));
        }
    }

    Err(io::Error::new(io::ErrorKind::NotFound, "USB Controller not found"))
}

/// Retrieves USB controller info for the disk in Linux.
#[cfg(target_os = "linux")]
pub fn get_usb_controller_info_linux(disk_path: &str) -> io::Result<String> {
    let output = Command::new("lsblk")
        .args(["-o", "NAME,MOUNTPOINT", "-J"])
        .output()?;

    let json_output = String::from_utf8_lossy(&output.stdout);
    let mut disk_device = String::new();

    for line in json_output.split('\n') {
        if line.contains(disk_path) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if let Some(name) = parts.get(0) {
                disk_device = name.trim_matches('"').to_string();
                break;
            }
        }
    }

    if disk_device.is_empty() {
        return Err(io::Error::new(io::ErrorKind::NotFound, "Disk device not found"));
    }

    let usb_output = Command::new("lsusb").output()?;
    let usb_info = String::from_utf8_lossy(&usb_output.stdout);

    let mut matched_device = String::new();
    for line in usb_info.split('\n') {
        if line.contains(&disk_device) {
            matched_device = line.to_string();
            break;
        }
    }

    if matched_device.is_empty() {
        return Err(io::Error::new(io::ErrorKind::NotFound, "USB Controller not found"));
    }

    Ok(format!("USB Controller Info: {}", matched_device))
}
