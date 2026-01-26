// src/backupio.rs
//! Minimal, dependency-free SMART reader for macOS 11-14.
//! Works for internal NVMe and SATA/USB-SATA drives that expose SMART.

#![cfg(target_os = "macos")]

use core_foundation_sys::base::kCFAllocatorDefault;
use io_kit_sys::{
    io_iterator_t, io_object_t, io_service_t, IOIteratorNext, IORegistryEntryCreateCFProperties,
    IOServiceGetMatchingServices, IOServiceMatching, KERN_SUCCESS,
};
use plist::{Dictionary, Value};
use std::{ffi::CString, io, ptr};

use crate::hardware_info::SmartMetrics; // <-- your shared struct

/// Public entry-point used by main.rs
pub fn smart_metrics_from_bsd(bsd_name: &str) -> io::Result<SmartMetrics> {
    // 1) Try NVMe first (Apple NVMe controller & 3rd-party cards)
    if let Ok(m) = pull_smart_dict("IONVMeSMARTUserClient", bsd_name).and_then(parse_nvme) {
        return Ok(m);
    }
    // 2) Fallback: SATA / USB-SATA
    if let Ok(m) = pull_smart_dict("IOSATSMARTUserClient", bsd_name).and_then(parse_sata) {
        return Ok(m);
    }

    Err(io::Error::new(
        io::ErrorKind::Other,
        "SMART user-client not found",
    ))
}

/// Low-level helper: find the first user-client of `class_name` whose parent
/// block-storage object has the given BSD name.  Returns its property dict.
fn pull_smart_dict(class_name: &str, bsd: &str) -> io::Result<Dictionary> {
    unsafe {
        let matching = IOServiceMatching(CString::new(class_name)?.as_ptr());
        if matching.is_null() {
            return Err(ioerr("failed to create matching dict"));
        }
        let mut it: io_iterator_t = 0;
        if IOServiceGetMatchingServices(0, matching, &mut it) != KERN_SUCCESS {
            return Err(ioerr("no services"));
        }
        let mut svc: io_service_t = IOIteratorNext(it);
        while svc != 0 {
            let mut cf_props = ptr::null_mut();
            IORegistryEntryCreateCFProperties(svc, &mut cf_props, kCFAllocatorDefault, 0);
            if cf_props.is_null() {
                svc = IOIteratorNext(it);
                continue;
            }
            let v = Value::from_cf_type_ref(cf_props);
            // The SMART user-client itself doesn\'t contain the BSD name; walk one
            // level up ("IOBlockStorageDevice") via the "Parent Root" key.
            if let Some(Value::Dictionary(dict)) = v.lookup("Parent Root") {
                if dict
                    .lookup("BSD Name")
                    .and_then(Value::as_string)
                    .map(|s| s.eq_ignore_ascii_case(bsd))
                    .unwrap_or(false)
                {
                    return v
                        .lookup("SMART Data")
                        .and_then(Value::as_dictionary)
                        .cloned()
                        .ok_or_else(|| ioerr("SMART Data key missing"));
                }
            }
            svc = IOIteratorNext(it);
        }
        Err(ioerr("service not found"))
    }
}

fn parse_nvme(d: Dictionary) -> io::Result<SmartMetrics> {
    let mut m = SmartMetrics::default();
    m.power_on_hours = d.lookup("PowerOnHours").and_then(Value::as_u64);
    m.unexpected_power_loss = d.lookup("UnsafeShutdowns").and_then(Value::as_u64);
    m.media_errors = d.lookup("MediaErrors").and_then(Value::as_u64);
    m.data_units_written = d.lookup("DataUnitsWritten").and_then(Value::as_u64);
    m.data_units_read = d.lookup("DataUnitsRead").and_then(Value::as_u64);
    m.percentage_used = d
        .lookup("PercentageUsed")
        .and_then(Value::as_u64)
        .map(|v| v as u8);
    m.temperature_c = d.lookup("Temperature").and_then(Value::as_f64);
    m.smart_overall_health = d
        .lookup("OverallHealth")
        .and_then(Value::as_string)
        .map(|s| s.to_string());
    Ok(m)
}

fn parse_sata(d: Dictionary) -> io::Result<SmartMetrics> {
    let mut m = SmartMetrics::default();
    m.smart_overall_health = d
        .lookup("OverallHealth")
        .and_then(Value::as_string)
        .map(|s| s.to_string());
    m.power_on_hours = d.lookup("PowerOnHours").and_then(Value::as_u64);
    m.power_cycle_count = d.lookup("PowerCycles").and_then(Value::as_u64);
    m.media_errors = d.lookup("MediaErrors").and_then(Value::as_u64);
    m.temperature_c = d.lookup("Temperature").and_then(Value::as_f64);
    Ok(m)
}

fn ioerr(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::Other, msg)
}
