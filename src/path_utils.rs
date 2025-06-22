use std::{io, path::{Path, PathBuf}};

/// Return the canonical block-device *node* (e.g. `/dev/nvme0n1`)
/// for a mount-point or any regular file on that filesystem.
/// Works transparently when the caller already passed a device path.
pub fn canonical_block<P: AsRef<Path>>(p: P) -> io::Result<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        use plist::Value;
        use std::process::Command;

        let out = Command::new("diskutil")
            .args(["info", "-plist", p.as_ref().to_str().unwrap()])
            .output()?;
        let dict = Value::from_reader_xml(&*out.stdout)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?
            .into_dictionary()
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "plist parse fail"))?;
        let dev = dict
            .get("DeviceNode")
            .and_then(Value::as_string)
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "no DeviceNode"))?;
        return Ok(PathBuf::from(dev));
    }

    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::MetadataExt;

        let md = std::fs::metadata(&p)?;
        let dev = md.dev();
        let major = unsafe { libc::major(dev) };
        let minor = unsafe { libc::minor(dev) };
        let sys = std::fs::read_link(format!("/sys/dev/block/{major}:{minor}"))?;
        let name = sys
            .file_name()
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "bad sysfs link"))?;
        return Ok(PathBuf::from("/dev").join(name));
    }

    #[cfg(target_os = "windows")]
    {
        use std::path::Component;
        let root = p
            .as_ref()
            .components()
            .next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "bad path"))?;
        if let Component::Prefix(pref) = root {
            if let std::path::Prefix::Disk(d) = pref.kind() {
                return Ok(PathBuf::from(format!("\\\\.\\{}:", d as char)));
            }
        }
        return Err(io::Error::new(io::ErrorKind::Other, "cannot resolve"));
    }

    #[allow(unreachable_code)]
    {
        Err(io::Error::new(io::ErrorKind::Other, "OS-unsupported"))
    }
}
