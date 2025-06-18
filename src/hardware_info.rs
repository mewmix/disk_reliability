use sysinfo::Disks;
use std::io;
use std::process::Command;
use std::collections::HashMap;
use std::time::Duration;

use rusb::{Context, DeviceHandle, UsbContext};

/// Retrieves information about the disk at the given path.
pub fn get_disk_info(disk_path: &str) -> io::Result<String> {
    let mut disks = Disks::new_with_refreshed_list();
    for disk in disks.list() {
        let mount_point_cow = disk.mount_point().to_string_lossy();
        let mount_point_str = mount_point_cow.as_ref();
        if disk_path.starts_with(mount_point_str) || mount_point_str.starts_with(disk_path) {
            return Ok(format!(
                "Disk: {}\nType: {:?}\nTotal Space: {:.2} GB\nAvailable: {:.2} GB",
                mount_point_str,
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

/// Lists connected USB devices and attempts to read their serial numbers using libusb.
pub fn get_usb_serial_numbers() -> io::Result<String> {
    let context = Context::new().map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    let mut info = String::new();
    let devices = context
        .devices()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

    for device in devices.iter() {
        if let Ok(desc) = device.device_descriptor() {
            // Filter for USB mass storage devices (class code 0x08). Some devices
            // report class code 0 and specify it in the interface descriptor.
            let mut is_mass_storage = desc.class_code() == 0x08;
            if !is_mass_storage {
                if let Ok(config) = device.active_config_descriptor() {
                    for interface in config.interfaces() {
                        for interface_desc in interface.descriptors() {
                            if interface_desc.class_code() == 0x08 {
                                is_mass_storage = true;
                                break;
                            }
                        }
                        if is_mass_storage {
                            break;
                        }
                    }
                }
            }

            if !is_mass_storage {
                continue;
            }

            let handle_result: Result<DeviceHandle<Context>, _> = device.open();
            if let Ok(handle) = handle_result {
                let language = handle
                    .read_languages(Duration::from_secs(1))
                    .ok()
                    .and_then(|l| l.into_iter().next());
                if let Some(lang) = language {
                    let manufacturer = handle
                        .read_manufacturer_string(lang, &desc, Duration::from_secs(1))
                        .unwrap_or_default();
                    let product = handle
                        .read_product_string(lang, &desc, Duration::from_secs(1))
                        .unwrap_or_default();
                    let serial = handle
                        .read_serial_number_string(lang, &desc, Duration::from_secs(1))
                        .unwrap_or_default();

                    if !serial.is_empty() {
                        info.push_str(&format!(
                            "USB Disk: {} {} - Serial: {}\n",
                            manufacturer, product, serial
                        ));
                    }
                }
            }
        }
    }

    if info.is_empty() {
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            "No USB disk serial numbers found",
        ))
    } else {
        Ok(info)
    }
}

/// Retrieves the serial number of the disk at the given path.
#[cfg(target_os = "linux")]
pub fn get_disk_serial_number(disk_path: &str) -> io::Result<String> {
    let output = Command::new("lsblk")
        .args(["-o", "NAME,MOUNTPOINT,SERIAL", "-P"])
        .output()?;
    let out_str = String::from_utf8_lossy(&output.stdout);
    for line in out_str.lines() {
        let mut name = "";
        let mut mount = "";
        let mut serial = "";
        for kv in line.split_whitespace() {
            if let Some(val) = kv.strip_prefix("NAME=") {
                name = val.trim_matches('"');
            } else if let Some(val) = kv.strip_prefix("MOUNTPOINT=") {
                mount = val.trim_matches('"');
            } else if let Some(val) = kv.strip_prefix("SERIAL=") {
                serial = val.trim_matches('"');
            }
        }
        if (!mount.is_empty() && disk_path.starts_with(mount)) ||
           disk_path.ends_with(name) {
            if !serial.is_empty() {
                return Ok(serial.to_string());
            }
        }
    }
    Err(io::Error::new(io::ErrorKind::NotFound, "Serial number not found"))
}

#[cfg(target_os = "windows")]
pub fn get_disk_serial_number(disk_path: &str) -> io::Result<String> {
    let output = Command::new("wmic")
        .args(["diskdrive", "get", "DeviceID,SerialNumber"])
        .output()?;
    let out_str = String::from_utf8_lossy(&output.stdout);
    for line in out_str.lines().skip(1) {
        let trimmed = line.trim();
        if trimmed.is_empty() { continue; }
        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        if parts.len() >= 2 {
            let device_id = parts[0];
            let serial = parts[1];
            if disk_path.contains(device_id) || disk_path.to_lowercase().starts_with(device_id.to_lowercase().as_str()) {
                return Ok(serial.to_string());
            }
        }
    }
    Err(io::Error::new(io::ErrorKind::NotFound, "Serial number not found"))
}
