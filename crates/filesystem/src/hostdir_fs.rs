//! Host-directory-backed guest file source.
//!
//! Indexes a host directory once (lowercase `/`-separated paths
//! relative to the root, like [`super::stfs_fs::StfsFs`]) and reads
//! file bytes lazily with an Arc cache. Used for extracted layouts
//! and system-update directories (e.g. dash), where no STFS
//! container exists. Read-only: the guest can never write through.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use x360_common::Result;
use x360_kernel::fs::{FsDirEntry, FsLookup, GuestFs};

/// Game files sourced from a host directory tree.
pub struct HostDirFs {
    /// Lowercase rel path -> real rel path (case recovery on
    /// case-sensitive hosts; on Windows they usually coincide).
    files: HashMap<String, PathBuf>,
    /// Lowercase dir path (""/"data"/...) -> children (original case).
    tree: HashMap<String, Vec<FsDirEntry>>,
    root: PathBuf,
    cache: Mutex<HashMap<String, Arc<[u8]>>>,
}

impl HostDirFs {
    /// Index `root` recursively. Unreadable entries and symlinks are
    /// skipped (no cycles, no surprises); errors surface only when
    /// `root` itself is unreadable.
    pub fn load(root: &Path) -> Result<Self> {
        use x360_common::EmuError;
        if !root.is_dir() {
            return Err(EmuError::Other(format!(
                "host dir backend needs a directory: {}",
                root.display()
            )));
        }
        let mut files = HashMap::new();
        let mut tree: HashMap<String, Vec<FsDirEntry>> = HashMap::new();
        tree.insert(String::new(), Vec::new());
        let mut stack = vec![PathBuf::new()];
        while let Some(rel) = stack.pop() {
            let full = root.join(&rel);
            let entries = std::fs::read_dir(&full)
                .map_err(|e| EmuError::Io(format!("{}: {}", full.display(), e)))?;
            for entry in entries.flatten() {
                let ft = match entry.file_type() {
                    Ok(t) => t,
                    Err(_) => continue,
                };
                if ft.is_symlink() {
                    continue;
                }
                let name_os = entry.file_name();
                let name = name_os.to_string_lossy().into_owned();
                let child_rel = if rel.as_os_str().is_empty() {
                    PathBuf::from(&name)
                } else {
                    rel.join(&name)
                };
                let key = child_rel
                    .to_string_lossy()
                    .replace('\\', "/")
                    .to_ascii_lowercase();
                let (dir, bare) = match key.rfind('/') {
                    Some(j) => (key[..j].to_string(), key[j + 1..].to_string()),
                    None => (String::new(), key.clone()),
                };
                if ft.is_dir() {
                    tree.entry(dir).or_default().push(FsDirEntry {
                        name: bare,
                        is_dir: true,
                        len: 0,
                    });
                    tree.entry(key).or_default();
                    stack.push(child_rel);
                } else if ft.is_file() {
                    let len = entry.metadata().map(|m| m.len()).unwrap_or(0);
                    tree.entry(dir).or_default().push(FsDirEntry {
                        name: bare,
                        is_dir: false,
                        len,
                    });
                    files.insert(key, child_rel);
                }
            }
        }
        Ok(Self {
            files,
            tree,
            root: root.to_path_buf(),
            cache: Mutex::new(HashMap::new()),
        })
    }

    /// Number of indexed files (for diagnostics).
    pub fn file_count(&self) -> usize {
        self.files.len()
    }
}

impl GuestFs for HostDirFs {
    fn lookup(&self, path: &str) -> FsLookup {
        if let Some(rel) = self.files.get(path) {
            if let Some(hit) = self.cache.lock().expect("fs cache").get(path) {
                return FsLookup::File(hit.clone());
            }
            match std::fs::read(self.root.join(rel)) {
                Ok(bytes) => {
                    let arc: Arc<[u8]> = Arc::from(bytes.into_boxed_slice());
                    self.cache
                        .lock()
                        .expect("fs cache")
                        .insert(path.to_string(), arc.clone());
                    FsLookup::File(arc)
                }
                Err(_) => FsLookup::NotFound,
            }
        } else if let Some(kids) = self.tree.get(path) {
            FsLookup::Dir(kids.clone())
        } else {
            FsLookup::NotFound
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unique_root(tag: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "x360-hostdirfs-{}-{}",
            tag,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        p
    }

    fn write_tree(root: &Path) {
        std::fs::create_dir_all(root.join("data/strings")).expect("mkdirs");
        std::fs::write(root.join("default.xex"), b"XEX2fake").expect("write xex");
        std::fs::write(root.join("data/strings/english.mo"), b"mobytes").expect("write mo");
    }

    #[test]
    fn hostdir_indexes_and_serves() {
        let root = unique_root("basic");
        write_tree(&root);
        let fs = HostDirFs::load(&root).expect("index");
        assert_eq!(fs.file_count(), 2);
        match fs.lookup("default.xex") {
            FsLookup::File(b) => assert_eq!(&b[..], b"XEX2fake"),
            _ => panic!("root file missing"),
        }
        // The kernel normalizes lookups to lowercase before calling
        // the backend; the index keeps original case for listings.
        match fs.lookup("data/strings/english.mo") {
            FsLookup::File(b) => assert_eq!(&b[..], b"mobytes"),
            _ => panic!("nested file missing"),
        }
        match fs.lookup("data/strings") {
            FsLookup::Dir(kids) => {
                assert!(kids.iter().any(|e| e.name == "english.mo" && !e.is_dir))
            }
            _ => panic!("dir listing missing"),
        }
        match fs.lookup("") {
            FsLookup::Dir(kids) => {
                assert!(kids.iter().any(|e| e.name == "data" && e.is_dir))
            }
            _ => panic!("root listing missing"),
        }
        assert!(matches!(fs.lookup("nope.bin"), FsLookup::NotFound));
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn hostdir_rejects_non_directories() {
        let root = unique_root("reject");
        std::fs::create_dir_all(&root).expect("mkdir");
        let file = root.join("f.bin");
        std::fs::write(&file, b"x").expect("write");
        assert!(HostDirFs::load(&file).is_err());
        assert!(HostDirFs::load(&root.join("missing")).is_err());
        std::fs::remove_dir_all(&root).ok();
    }
}
