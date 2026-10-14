//! STFS-backed guest file source.
//!
//! Indexes an STFS package once (full paths via the entry parent
//! chain) and extracts file bytes lazily with an Arc cache, so the
//! kernel serves real game bytes without holding every asset
//! extracted at once.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use x360_common::Result;
use x360_kernel::fs::{FsDirEntry, FsLookup, GuestFs};

use super::stfs::{StfsEntry, StfsImage};

/// Game files sourced from an STFS package in memory.
pub struct StfsFs {
    data: Arc<[u8]>,
    /// Lowercase full path -> entry (files only).
    files: HashMap<String, StfsEntry>,
    /// Lowercase dir path (""/"data"/...) -> children.
    tree: HashMap<String, Vec<FsDirEntry>>,
    cache: Mutex<HashMap<String, Arc<[u8]>>>,
}

impl StfsFs {
    /// Index `data` (whole package file). Paths are lowercase
    /// `/`-separated, relative to the package root.
    pub fn load(data: Arc<[u8]>) -> Result<Self> {
        let img = StfsImage::open(&data)?;
        let entries = img.list_files()?;
        // Full path per entry via the parent chain (parent = table
        // index, 0xFFFF = root). Fixed-point: parents usually precede
        // children, but never assume it.
        let mut paths: HashMap<usize, String> = HashMap::new();
        let mut changed = true;
        while changed {
            changed = false;
            for (i, e) in entries.iter().enumerate() {
                if paths.contains_key(&i) {
                    continue;
                }
                if e.parent == 0xFFFF {
                    paths.insert(i, e.name.to_ascii_lowercase());
                    changed = true;
                } else if let Some(p) = paths.get(&(e.parent as usize)).cloned() {
                    paths.insert(i, format!("{}/{}", p, e.name.to_ascii_lowercase()));
                    changed = true;
                }
            }
        }
        let mut files = HashMap::new();
        let mut tree: HashMap<String, Vec<FsDirEntry>> = HashMap::new();
        tree.insert(String::new(), Vec::new());
        for (i, e) in entries.iter().enumerate() {
            let full = match paths.get(&i) {
                Some(p) => p.clone(),
                None => continue, // orphaned entry: unreachable, skip
            };
            let (dir, bare) = match full.rfind('/') {
                Some(j) => (full[..j].to_string(), full[j + 1..].to_string()),
                None => (String::new(), full.clone()),
            };
            tree.entry(dir.clone()).or_default().push(FsDirEntry {
                name: bare,
                is_dir: e.is_dir,
                len: e.length as u64,
            });
            if e.is_dir {
                tree.entry(full).or_default();
            } else {
                files.insert(full, e.clone());
            }
        }
        Ok(Self {
            data,
            files,
            tree,
            cache: Mutex::new(HashMap::new()),
        })
    }
}

impl GuestFs for StfsFs {
    fn lookup(&self, path: &str) -> FsLookup {
        if let Some(entry) = self.files.get(path) {
            // Cached extract, else SHA1-verified read from the package.
            if let Some(hit) = self.cache.lock().expect("fs cache").get(path) {
                return FsLookup::File(hit.clone());
            }
            let img = match StfsImage::open(&self.data) {
                Ok(img) => img,
                Err(_) => return FsLookup::NotFound,
            };
            match img.read_file(entry) {
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

    struct MemFs {
        files: HashMap<String, Vec<u8>>,
    }

    impl GuestFs for MemFs {
        fn lookup(&self, path: &str) -> FsLookup {
            if let Some(b) = self.files.get(path) {
                return FsLookup::File(Arc::from(b.as_slice()));
            }
            let prefix = if path.is_empty() {
                String::new()
            } else {
                format!("{}/", path)
            };
            let mut kids = Vec::new();
            for k in self.files.keys() {
                if let Some(rest) = k.strip_prefix(&prefix) {
                    if !rest.contains('/') {
                        kids.push(FsDirEntry {
                            name: rest.to_string(),
                            is_dir: false,
                            len: self.files[k].len() as u64,
                        });
                    }
                }
            }
            if kids.is_empty() {
                FsLookup::NotFound
            } else {
                FsLookup::Dir(kids)
            }
        }
    }

    #[test]
    fn mem_backend_lookup_shapes() {
        let fs = MemFs {
            files: [("a/b.bin".to_string(), vec![1, 2, 3])].into(),
        };
        assert!(matches!(fs.lookup("a/b.bin"), FsLookup::File(_)));
        assert!(matches!(fs.lookup("a"), FsLookup::Dir(_)));
        assert!(matches!(fs.lookup("zzz"), FsLookup::NotFound));
    }

    /// STFS index shape against the real Braid package (env-gated).
    #[test]
    fn stfs_index_has_game_files() {
        let path = match std::env::var("X360_STFS_FILE") {
            Ok(p) => p,
            Err(_) => return,
        };
        let bytes = std::fs::read(&path).expect("read package");
        let fs = StfsFs::load(Arc::from(bytes.into_boxed_slice())).expect("index");
        match fs.lookup("data/strings/english.mo") {
            FsLookup::File(b) => assert_eq!(b.len(), 37173),
            FsLookup::Dir(_) => panic!("english.mo is a dir"),
            FsLookup::NotFound => panic!("english.mo missing"),
        }
        match fs.lookup("data/strings") {
            FsLookup::Dir(kids) => {
                assert!(kids.iter().any(|k| k.name == "english.mo" && !k.is_dir))
            }
            _ => panic!("strings not a dir"),
        }
        assert!(matches!(fs.lookup("nope/nothing"), FsLookup::NotFound));
    }
}
