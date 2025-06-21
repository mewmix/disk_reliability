#[cfg(target_os = "macos")]
use std::io::{self, ErrorKind};
#[cfg(target_os = "macos")]
use std::process::Command;

#[cfg(target_os = "macos")]
use plist::Value;
#[cfg(target_os = "macos")]
use serde_json::{Map, Value as JsonValue};

#[cfg(target_os = "macos")]
pub fn usb_storage_report(path: &str) -> io::Result<String> {
    let bsd = get_bsd_name_from_path(path).ok_or_else(|| {
        io::Error::new(ErrorKind::NotFound, "Could not resolve BSD name for path")
    })?;

    let output = Command::new("system_profiler")
        .args(["SPUSBDataType", "-json", "-detailLevel", "mini"])
        .output()?;

    let json: JsonValue = serde_json::from_slice(&output.stdout)
        .map_err(|e| io::Error::new(ErrorKind::Other, e))?;
    let items = json
        .get("SPUSBDataType")
        .and_then(|v| v.as_array())
        .ok_or_else(|| io::Error::new(ErrorKind::Other, "Unexpected system_profiler output"))?;

    let mut stack = Vec::new();
    let path_nodes = search(items, &bsd, &mut stack)
        .ok_or_else(|| io::Error::new(ErrorKind::NotFound, "USB path not found"))?;

    let mut out = String::new();
    for (depth, node) in path_nodes.iter().enumerate() {
        if let Some(map) = node.as_object() {
            pretty_usb_node(map, depth * 2, &mut out);
        }
    }

    Ok(out)
}

#[cfg(target_os = "macos")]
fn search<'a>(value: &'a JsonValue, bsd: &str, stack: &mut Vec<&'a JsonValue>) -> Option<Vec<&'a JsonValue>> {
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
            out.push_str(&format!("{ind}  \u{26a0} draws {req} mA > {avail} mA supplied\n"));
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

#[cfg(target_os = "macos")]
fn get_bsd_name_from_path(path: &str) -> Option<String> {
    let output = Command::new("diskutil")
        .arg("info")
        .arg("-plist")
        .arg(path)
        .output()
        .ok()?;
    let plist = Value::from_reader_xml(&*output.stdout).ok()?;
    plist
        .as_dictionary()
        .and_then(|dict| dict.get("DeviceNode"))
        .and_then(|node| node.as_string())
        .map(|s| s.to_string())
}
