//! ISO / STFS / extracted directory handling.

use std::path::{Path, PathBuf};
use x360_common::{EmuError, Result};

pub mod hostdir_fs;
pub mod stfs;
pub mod stfs_fs;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentKind {
    ExtractedDir,
    Iso,
    Stfs,
    Unknown,
}

/// Identify content by magic/path. No execution implied.
pub fn identify(path: &Path) -> Result<ContentKind> {
    if path.is_dir() {
        // Extracted game must contain default.xex (case-insensitive check).
        let has_xex = std::fs::read_dir(path)
            .map_err(|e| EmuError::Io(e.to_string()))?
            .filter_map(|e| e.ok())
            .any(|e| e.file_name().to_string_lossy().to_lowercase() == "default.xex");
        if has_xex {
            return Ok(ContentKind::ExtractedDir);
        }
        return Ok(ContentKind::Unknown);
    }
    let mut f = std::fs::File::open(path)?;
    use std::io::Read;
    let mut magic = [0u8; 4];
    let n = f
        .read(&mut magic)
        .map_err(|e| EmuError::Io(e.to_string()))?;
    if n < 4 {
        return Ok(ContentKind::Unknown);
    }
    // GDFX/XDVDFS ISO starts with "MICRO" at sector 32; check common magics.
    if &magic == b"XEX2" {
        return Ok(ContentKind::Unknown); // single XEX, handled by loader
    }
    // STFS containers (CON/PIRS/LIVE, incl. extensionless GOD files).
    if &magic == b"CON " || &magic == b"PIRS" || &magic == b"LIVE" {
        return Ok(ContentKind::Stfs);
    }
    let ext = path
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or_default()
        .to_lowercase();
    match ext.as_str() {
        "iso" => Ok(ContentKind::Iso),
        "stfs" | "xbla" | "fxe" => Ok(ContentKind::Stfs),
        _ => Ok(ContentKind::Unknown),
    }
}

/// Resolve default.xex inside an extracted directory.
pub fn default_xex_in(path: &Path) -> Result<PathBuf> {
    let cand = path.join("default.xex");
    if cand.exists() {
        return Ok(cand);
    }
    // Case-insensitive fallback.
    for e in std::fs::read_dir(path)? {
        let e = e.map_err(|e| EmuError::Io(e.to_string()))?;
        if e.file_name().to_string_lossy().to_lowercase() == "default.xex" {
            return Ok(e.path());
        }
    }
    Err(EmuError::Other(format!(
        "no default.xex in {}",
        path.display()
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn missing_xex_is_error() {
        let dir = std::env::temp_dir().join("x360-fs-test-empty");
        let _ = std::fs::create_dir_all(&dir);
        assert!(default_xex_in(&dir).is_err());
    }
}
