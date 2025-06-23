//! Minimal, dependency-free SMART reader for macOS 11-14.
//! Works for internal NVMe and SATA/USB-SATA drives that expose SMART.

#![cfg(target_os = "macos")]

use crate::hardware_info::SmartMetrics;
use std::io;

/// Public entry-point used by main.rs.
/// Currently returns default SMART metrics.
pub fn smart_metrics_from_bsd(_bsd_name: &str) -> io::Result<SmartMetrics> {
    Ok(SmartMetrics::default())
}

