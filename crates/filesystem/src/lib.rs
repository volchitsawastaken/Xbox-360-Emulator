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

/// Normalize a backend lookup path to lowercase `/`-separated form
/// relative to the game root (`""` = root).
///
/// Defensive: the kernel normalizes guest paths before calling, but
/// direct callers may pass `\` separators, a leading `/`, repeated
/// separators, `.`/`..`, trailing slashes, or mixed case. `..` above
/// the root clamps (never escapes).
pub fn normalize_lookup(path: &str) -> String {
    let lower = path.replace('\\', "/").to_ascii_lowercase();
    let mut parts: Vec<&str> = Vec::new();
    for comp in lower.split('/') {
        match comp {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            c => parts.push(c),
        }
    }
    parts.join("/")
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

    #[test]
    fn normalize_lookup_shapes() {
        assert_eq!(normalize_lookup(""), "");
        assert_eq!(normalize_lookup("/"), "");
        assert_eq!(normalize_lookup("a/b.bin"), "a/b.bin");
        assert_eq!(normalize_lookup("A/B.BIN"), "a/b.bin");
        assert_eq!(normalize_lookup("a\\b\\c.bin"), "a/b/c.bin");
        assert_eq!(normalize_lookup("/a/b"), "a/b");
        assert_eq!(normalize_lookup("a//b"), "a/b");
        assert_eq!(normalize_lookup("a/./b"), "a/b");
        assert_eq!(normalize_lookup("a/b/"), "a/b");
        assert_eq!(normalize_lookup("a/../b"), "b");
        assert_eq!(normalize_lookup("../b"), "b");
        assert_eq!(normalize_lookup(".."), "");
        assert_eq!(normalize_lookup("a/../../b"), "b");
    }

    #[test]
    fn identify_xex_magic_is_unknown() {
        let dir = std::env::temp_dir();
        let p = dir.join("x360-fs-test-xex2.bin");
        std::fs::write(&p, b"XEX2rest").expect("write xex magic");
        assert_eq!(identify(&p).expect("identify"), ContentKind::Unknown);
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn identify_stfs_magics() {
        let dir = std::env::temp_dir();
        for (tag, magic) in [
            ("con", b"CON ".as_slice()),
            ("pirs", b"PIRS".as_slice()),
            ("live", b"LIVE".as_slice()),
        ] {
            let p = dir.join(format!("x360-fs-test-{}.bin", tag));
            let mut bytes = magic.to_vec();
            bytes.extend_from_slice(&[0u8; 16]);
            std::fs::write(&p, &bytes).expect("write magic");
            assert_eq!(
                identify(&p).expect("identify"),
                ContentKind::Stfs,
                "magic {:?}",
                magic
            );
            std::fs::remove_file(&p).ok();
        }
    }

    #[test]
    fn identify_short_file_is_unknown() {
        let dir = std::env::temp_dir();
        let p = dir.join("x360-fs-test-short.bin");
        std::fs::write(&p, b"AB").expect("write short");
        assert_eq!(identify(&p).expect("identify"), ContentKind::Unknown);
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn identify_iso_extension() {
        let dir = std::env::temp_dir();
        let p = dir.join("x360-fs-test-disk.iso");
        std::fs::write(&p, [0xABu8; 16]).expect("write iso");
        assert_eq!(identify(&p).expect("identify"), ContentKind::Iso);
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn identify_extracted_dir_shapes() {
        let base = std::env::temp_dir().join(format!(
            "x360-fs-test-ident-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let with = base.join("with");
        let without = base.join("without");
        std::fs::create_dir_all(&with).expect("mkdir with");
        std::fs::create_dir_all(&without).expect("mkdir without");
        std::fs::write(with.join("DEFAULT.XEX"), b"XEX2fake").expect("write xex");
        assert_eq!(
            identify(&with).expect("identify"),
            ContentKind::ExtractedDir
        );
        assert_eq!(identify(&without).expect("identify"), ContentKind::Unknown);
        assert_eq!(
            default_xex_in(&with)
                .expect("resolve")
                .file_name()
                .expect("name")
                .to_string_lossy()
                .to_lowercase(),
            "default.xex"
        );
        std::fs::remove_dir_all(&base).ok();
    }
}
