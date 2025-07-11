// src/mac_usb_report.rs
use dashmap::DashMap;
use once_cell::sync::Lazy;

#[cfg(target_os = "macos")]
use std::io::{self, ErrorKind};
#[cfg(target_os = "macos")]
use std::process::Command;

#[cfg(target_os = "macos")]
use crate::hardware_info::get_bsd_name_from_path;
#[cfg(target_os = "macos")]
use plist::Value;
#[cfg(target_os = "macos")]
use serde_json::{Map, Value as JsonValue};

/// ----------  GLOBAL CACHE  ----------
#[cfg(target_os = "macos")]
static USB_JSON: Lazy<DashMap<(), JsonValue>> = Lazy::new(|| DashMap::new());

fn system_profiler_json() -> io::Result<JsonValue> {
    if let Some(v) = USB_JSON.get(&()) {
        return Ok(v.clone());
    }
    let output = Command::new("system_profiler")
        .args(["SPUSBDataType", "-json", "-detailLevel", "mini"])
        .output()?;
    let json: JsonValue =
        serde_json::from_slice(&output.stdout).map_err(|e| io::Error::new(ErrorKind::Other, e))?;
    USB_JSON.insert((), json.clone());
    Ok(json)
}

/// Pretty-prints the full device-path tree (used only when --verbose)
#[cfg(target_os = "macos")]
pub fn usb_storage_report(path: &str) -> io::Result<String> {
    let bsd = get_bsd_name_from_path(path).ok_or_else(|| {
        io::Error::new(ErrorKind::NotFound, "Could not resolve BSD name for path")
    })?;

    let json = system_profiler_json()?;
    let root = json
        .get("SPUSBDataType")
        .and_then(|n| n.get(0))
        .and_then(|n| n.get("_items"))
        .and_then(|n| n.as_array())
        .and_then(|arr| arr.last())
        .ok_or_else(|| io::Error::new(ErrorKind::Other, "Unexpected system_profiler output"))?;

    let mut stack = Vec::new();
    let path_nodes = search(root, &bsd, &mut stack)
        .ok_or_else(|| io::Error::new(ErrorKind::NotFound, "USB path not found"))?;

    let mut out = String::new();
    for (depth, node) in path_nodes.iter().enumerate() {
        if let Some(map) = node.as_object() {
            pretty_usb_node(map, depth * 2, &mut out);
        }
    }

    Ok(out)
}

/// One-liner summary for normal runs.
#[cfg(target_os = "macos")]
pub fn usb_storage_summary(path: &str) -> io::Result<String> {
    let bsd = get_bsd_name_from_path(path).ok_or_else(|| {
        io::Error::new(ErrorKind::NotFound, "Could not resolve BSD name for path")
    })?;

    let json = system_profiler_json()?;
    let root = json
        .get("SPUSBDataType")
        .and_then(|n| n.get(0))
        .and_then(|n| n.get("_items"))
        .and_then(|n| n.as_array())
        .and_then(|arr| arr.last())
        .ok_or_else(|| io::Error::new(ErrorKind::Other, "Unexpected system_profiler output"))?;

    // Re-use the existing search() helper to fetch the node chain.
    let mut stack = Vec::new();
    let path_nodes = search(root, &bsd, &mut stack)
        .ok_or_else(|| io::Error::new(ErrorKind::NotFound, "USB path not found"))?;

    // Last entry is the actual storage device; its parent is the hub/port.
    let dev = path_nodes.last().and_then(|n| n.as_object());
    let hub = if path_nodes.len() >= 2 {
        path_nodes[path_nodes.len() - 2].as_object()
    } else {
        None
    };

    let dev_name = dev
        .and_then(|d| d.get("_name").and_then(|v| v.as_str()))
        .unwrap_or("USB Device");
    let mfr = dev
        .and_then(|d| d.get("manufacturer").and_then(|v| v.as_str()))
        .unwrap_or("");
    let speed = hub
        .and_then(|h| h.get("speed").and_then(|v| v.as_str()))
        .unwrap_or("");
    let req_ma = dev
        .and_then(|d| d.get("current_required").and_then(|v| v.as_u64()))
        .unwrap_or(0);
    let avail_ma = hub
        .and_then(|h| h.get("current_available").and_then(|v| v.as_u64()))
        .unwrap_or(0);

    Ok(format!(
        "{mfr} {dev_name} @ {speed} (uses {req_ma} mA / {avail_ma} mA)"
    ))
}

#[cfg(target_os = "macos")]
fn search<'a>(
    value: &'a JsonValue,
    bsd: &str,
    stack: &mut Vec<&'a JsonValue>,
) -> Option<Vec<&'a JsonValue>> {
    match value {
        JsonValue::Object(map) => {
            stack.push(value);
            if map
                .get("bsd_name")
                .and_then(|v| v.as_str())
                .map_or(false, |s| s.eq_ignore_ascii_case(bsd))
                || map
                    .get("BSD Name")
                    .and_then(|v| v.as_str())
                    .map_or(false, |s| s.eq_ignore_ascii_case(bsd))
            {
                return Some(stack.clone());
            }
            if let Some(res) = map.get("volumes").and_then(|v| search(v, bsd, stack)) {
                return Some(res);
            }
            for val in map.values() {
                if let Some(res) = search(val, bsd, stack) {
                    return Some(res);
                }
            }
            stack.pop();
        }
        JsonValue::Array(arr) => {
            for val in arr {
                if let Some(res) = search(val, bsd, stack) {
                    return Some(res);
                }
            }
        }
        _ => {}
    }
    None
}

#[cfg(target_os = "macos")]
fn pretty_usb_node(node: &Map<String, JsonValue>, indent: usize, out: &mut String) {
    let ind = " ".repeat(indent);
    if let Some(name) = node.get("_name").and_then(|v| v.as_str()) {
        out.push_str(&format!("{ind}{name}\n"));
    }

    const KEYS: &[&str] = &[
        "vendor_id",
        "product_id",
        "serial_num",
        "speed",
        "manufacturer",
        "location_id",
        "current_available",
        "current_required",
        "extra_current",
        "pci_device_id",
        "pci_revision_id",
        "pci_vendor_id",
    ];

    for key in KEYS {
        if let Some(v) = node.get(*key) {
            if let Some(s) = v.as_str() {
                out.push_str(&format!("{ind}  {key}: {s}\n"));
            } else if let Some(n) = v.as_i64() {
                out.push_str(&format!("{ind}  {key}: {n}\n"));
            }
        }
    }

    if let (Some(req), Some(avail)) = (
        node.get("current_required").and_then(|v| v.as_u64()),
        node.get("current_available").and_then(|v| v.as_u64()),
    ) {
        if req > avail && req != 0 {
            out.push_str(&format!(
                "{ind}  \u{26a0} draws {req} mA > {avail} mA supplied\n"
            ));
        }
    }

    if let Some(subs) = node.get("volumes").and_then(|v| v.as_array()) {
        for sub in subs {
            if let Some(map) = sub.as_object() {
                pretty_usb_node(map, indent + 2, out);
            }
        }
    }
}
