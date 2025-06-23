use std::path::{Path, PathBuf};
use std::io;

use crate::hardware_info::{self, SmartMetrics};

#[derive(Debug, Default)]
pub struct ControllerNode {
    pub name: String,
    pub class: Option<String>,
}

#[derive(Debug)]
pub enum BusType {
    Usb,
    Sata,
    Nvme,
    Scsi,
    Thunderbolt,
    Other(String),
}

impl Default for BusType {
    fn default() -> Self {
        BusType::Other("unknown".into())
    }
}

#[derive(Debug, Default)]
pub struct NvmeSmartLog {
    pub temperature: Option<f64>,
    pub power_on_hours: Option<u64>,
    pub unsafe_shutdowns: Option<u64>,
}

#[derive(Debug, Default)]
pub struct AtaIdentify {
    pub model: Option<String>,
    pub firmware: Option<String>,
    pub serial: Option<String>,
}

#[derive(Debug, Default)]
pub struct FullDriveReport {
    pub logical_path: Option<PathBuf>,
    pub block_device: Option<String>,
    pub mount_point: Option<String>,
    pub volume_uuid: Option<String>,
    pub fs_type: Option<String>,
    pub partition_scheme: Option<String>,

    pub size_bytes: Option<u64>,
    pub block_size: Option<u32>,
    pub is_ssd: Option<bool>,
    pub rotational: Option<bool>,

    pub bus: Option<BusType>,
    pub controller_chain: Vec<ControllerNode>,

    pub model: Option<String>,
    pub serial: Option<String>,
    pub firmware: Option<String>,
    pub protocol: Option<String>,

    pub smart_info: Option<SmartMetrics>,
    pub nvme_info: Option<NvmeSmartLog>,
    pub identify_info: Option<AtaIdentify>,

    pub errors: Vec<String>,
}

/// Probe the given path and attempt to populate a [`FullDriveReport`].
///
/// The current implementation focuses on macOS and merely wires together
/// existing helpers.  Other platforms return `Ok(Default::default())` for now.
pub fn probe_drive<P: AsRef<Path>>(path: P) -> io::Result<FullDriveReport> {
    let mut report = FullDriveReport::default();
    let p = path.as_ref();
    report.logical_path = Some(p.to_path_buf());

    #[cfg(target_os = "macos")]
    {
        use plist::Value;
        use std::process::Command;

        let output = Command::new("diskutil")
            .args(["info", "-plist", p.to_str().unwrap_or("")])
            .output()?;
        let plist = Value::from_reader_xml(&*output.stdout)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        if let Some(dict) = plist.as_dictionary() {
            if let Some(node) = dict.get("DeviceNode").and_then(Value::as_string) {
                report.block_device = Some(node.to_string());
            }
            if let Some(uuid) = dict.get("VolumeUUID").and_then(Value::as_string) {
                report.volume_uuid = Some(uuid.to_string());
            }
            if let Some(fs) = dict.get("FilesystemType").and_then(Value::as_string) {
                report.fs_type = Some(fs.to_string());
            }
            if let Some(sz) = dict.get("TotalSize").and_then(Value::as_u64) {
                report.size_bytes = Some(sz);
            }
            if let Some(bs) = dict.get("DeviceBlockSize").and_then(Value::as_u64) {
                report.block_size = Some(bs as u32);
            }
        }

        if let Some(ref bdev) = report.block_device {
            if let Some(bsd) = Path::new(bdev)
                .file_name()
                .and_then(|s| s.to_str())
            {
                if let Ok(m) = hardware_info::smart_metrics(bsd) {
                    report.smart_info = Some(m);
                }
            }
        }

        // TODO: populate controller_chain and identify/nvme info
    }

    Ok(report)
}

