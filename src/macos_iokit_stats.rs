//! Minimal, dependency-free SMART reader for macOS 11-14.
//! Works for internal NVMe and SATA/USB-SATA drives that expose SMART.

#![cfg(target_os = "macos")]

use core_foundation_sys::base::{kCFAllocatorDefault, CFRelease};
use core_foundation_sys::data::{CFDataGetBytePtr, CFDataGetLength};
use core_foundation_sys::propertylist::{
    kCFPropertyListXMLFormat_v1_0, CFPropertyListCreateData, CFPropertyListRef,
};
use io_kit_sys::{
    types::{io_iterator_t, io_object_t, io_service_t},
    IOIteratorNext, IOObjectRelease, IORegistryEntryCreateCFProperties,
    IOServiceGetMatchingServices, IOServiceMatching,
};
use mach2::kern_return::KERN_SUCCESS;
use plist::{Dictionary, Value};
use std::{ffi::CString, io, ptr};

use crate::hardware_info::SmartMetrics; // <-- your shared struct

/// Convert a CoreFoundation property list into a [`plist::Value`].
unsafe fn cf_plist_to_value(plist: CFPropertyListRef) -> io::Result<Value> {
    let data = CFPropertyListCreateData(
        kCFAllocatorDefault,
        plist,
        kCFPropertyListXMLFormat_v1_0,
        0,
        std::ptr::null_mut(),
    );
    if data.is_null() {
        return Err(ioerr("CFPropertyListCreateData failed"));
    }
    let len = CFDataGetLength(data) as usize;
    let ptr = CFDataGetBytePtr(data);
    let slice = std::slice::from_raw_parts(ptr, len);
    let value = Value::from_reader_xml(slice).map_err(|_| ioerr("plist parse failed"));
    CFRelease(data as _);
    value
}

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
                IOObjectRelease(svc);
                svc = IOIteratorNext(it);
                continue;
            }
            let v = cf_plist_to_value(cf_props as CFPropertyListRef)?;
            CFRelease(cf_props as _);
            // The SMART user-client itself doesn't contain the BSD name; walk one
            // level up ("IOBlockStorageDevice") via the "Parent Root" key.
            if let Some(Value::Dictionary(dict)) = v
                .as_dictionary()
                .and_then(|root| root.get("Parent Root"))
                .and_then(Value::as_dictionary)
            {
                if dict
                    .get("BSD Name")
                    .and_then(Value::as_string)
                    .map(|s| s.eq_ignore_ascii_case(bsd))
                    .unwrap_or(false)
                {
                    let res = v
                        .as_dictionary()
                        .and_then(|root| root.get("SMART Data"))
                        .and_then(Value::as_dictionary)
                        .cloned()
                        .ok_or_else(|| ioerr("SMART Data key missing"));
                    IOObjectRelease(svc);
                    IOObjectRelease(it as io_object_t);
                    return res;
                }
            }
            IOObjectRelease(svc);
            svc = IOIteratorNext(it);
        }
        IOObjectRelease(it as io_object_t);
        Err(ioerr("service not found"))
    }
}

fn parse_nvme(d: Dictionary) -> io::Result<SmartMetrics> {
    let mut m = SmartMetrics::default();
    m.power_on_hours = d.get("PowerOnHours").and_then(Value::as_unsigned_integer);
    m.unexpected_power_loss = d
        .get("UnsafeShutdowns")
        .and_then(Value::as_unsigned_integer);
    m.media_errors = d.get("MediaErrors").and_then(Value::as_unsigned_integer);
    m.data_units_written = d
        .get("DataUnitsWritten")
        .and_then(Value::as_unsigned_integer);
    m.data_units_read = d.get("DataUnitsRead").and_then(Value::as_unsigned_integer);
    m.percentage_used = d
        .get("PercentageUsed")
        .and_then(Value::as_unsigned_integer)
        .map(|v| v as u8);
    m.temperature_c = d.get("Temperature").and_then(Value::as_real);
    m.smart_overall_health = d
        .get("OverallHealth")
        .and_then(Value::as_string)
        .map(|s| s.to_string());
    Ok(m)
}

fn parse_sata(d: Dictionary) -> io::Result<SmartMetrics> {
    let mut m = SmartMetrics::default();
    m.smart_overall_health = d
        .get("OverallHealth")
        .and_then(Value::as_string)
        .map(|s| s.to_string());
    m.power_on_hours = d.get("PowerOnHours").and_then(Value::as_unsigned_integer);
    m.power_cycle_count = d.get("PowerCycles").and_then(Value::as_unsigned_integer);
    m.media_errors = d.get("MediaErrors").and_then(Value::as_unsigned_integer);
    m.temperature_c = d.get("Temperature").and_then(Value::as_real);
    Ok(m)
}

fn ioerr(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::Other, msg)
}
