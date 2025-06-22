use crate::drive_descriptor::BusType;

#[derive(Debug)]
pub struct ControllerNode {
    pub label: String,
    pub bus: BusType,
    pub vid: Option<u16>,
    pub pid: Option<u16>,
}

pub fn controller_tree_for_path(p: &str) -> std::io::Result<Vec<ControllerNode>> {
    #[cfg(target_os = "linux")]
    {
        return linux_tree(p);
    }
    #[cfg(target_os = "macos")]
    {
        return mac_tree(p);
    }
    #[cfg(target_os = "windows")]
    {
        return win_tree(p);
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::Other,
        "OS-unsupported",
    ))
}

#[cfg(target_os = "linux")]
fn linux_tree(p: &str) -> std::io::Result<Vec<ControllerNode>> {
    use std::{fs, io, path::Path};
    let path = crate::path_utils::canonical_block(p)?;
    let dev = fs::canonicalize(&path)?;
    let name = dev
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "invalid device"))?;
    let mut path = fs::canonicalize(Path::new("/sys/block").join(name).join("device"))?;
    let mut nodes_rev = Vec::new();
    loop {
        let label = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_string();
        let bus = fs::read_link(path.join("subsystem"))
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

        let vid = fs::read_to_string(path.join("idVendor"))
            .ok()
            .and_then(|s| u16::from_str_radix(s.trim(), 16).ok());
        let pid = fs::read_to_string(path.join("idProduct"))
            .ok()
            .and_then(|s| u16::from_str_radix(s.trim(), 16).ok());
        nodes_rev.push(ControllerNode {
            label,
            bus,
            vid,
            pid,
        });

        if path.starts_with("/sys/devices") && path.parent().is_none() {
            break;
        }
        if !path.pop() {
            break;
        }
    }
    nodes_rev.reverse();
    Ok(nodes_rev)
}

#[cfg(target_os = "macos")]
fn mac_tree(p: &str) -> std::io::Result<Vec<ControllerNode>> {
    use plist::Value;
    use std::{io, process::Command};

    let dev = crate::path_utils::canonical_block(p)?;
    let dev_str = dev
        .to_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "utf-8 path"))?;

    let out = Command::new("diskutil")
        .args(["info", "-plist", dev_str])
        .output()?;
    let dict = Value::from_reader_xml(&*out.stdout)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?
        .into_dictionary()
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "plist parse"))?;

    let path_field = dict
        .get("DeviceTreePath")
        .and_then(Value::as_string)
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "missing DeviceTreePath"))?;

    let mut nodes = Vec::<ControllerNode>::new();
    for segment in path_field
        .trim_start_matches("IODeviceTree:")
        .trim_start_matches('/')
        .split('/')
    {
        let bus = if segment.contains("USB") || segment.contains("XHC") {
            BusType::Usb
        } else if segment.contains("PCI") {
            BusType::Thunderbolt
        } else {
            BusType::Unknown
        };
        nodes.push(ControllerNode {
            label: segment.to_string(),
            bus,
            vid: None,
            pid: None,
        });
    }

    Ok(nodes)
}

#[cfg(target_os = "windows")]
fn win_tree(p: &str) -> std::io::Result<Vec<ControllerNode>> {
    let _ = crate::path_utils::canonical_block(p)?;
    Ok(Vec::new())
}
