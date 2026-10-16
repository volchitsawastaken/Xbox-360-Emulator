//! STFS-backed guest file source.
//!
//! Indexes an STFS package once (full paths via the entry parent
//! chain) and extracts file bytes lazily with an Arc cache, so the
//! kernel serves real game bytes without holding every asset
//! extracted at once.
//!
//! Lookups normalize defensively via [`super::normalize_lookup`]
//! (case, `\` separators, leading `/`, `.`/`..`), matching the
//! kernel's canonical form.

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
        let key = super::normalize_lookup(path);
        if let Some(entry) = self.files.get(&key) {
            // Cached extract, else SHA1-verified read from the package.
            if let Some(hit) = self.cache.lock().expect("fs cache").get(&key) {
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
                        .insert(key, arc.clone());
                    FsLookup::File(arc)
                }
                Err(_) => FsLookup::NotFound,
            }
        } else if let Some(kids) = self.tree.get(&key) {
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

    /// Synthetic package: dir `data` + file `data/english.mo` (3 bytes)
    /// + one orphaned entry (bad parent, skipped). No retail bytes.
    fn synthetic_package() -> Vec<u8> {
        use sha1::{Digest, Sha1};
        const END: u32 = 0xFF_FFFF;
        let mut v = vec![0u8; 0x4000];
        v[0..4].copy_from_slice(b"LIVE");
        v[0x340..0x344].copy_from_slice(&0x1000u32.to_be_bytes());
        let vd = 0x379;
        v[vd] = 0x24;
        v[vd + 1] = 0;
        v[vd + 2] = 0x01; // read-only
        v[vd + 3..vd + 5].copy_from_slice(&1u16.to_be_bytes());
        v[vd + 5..vd + 8].copy_from_slice(&[0, 0, 0]);
        v[vd + 0x1C..vd + 0x20].copy_from_slice(&8u32.to_be_bytes());
        v[0x3A9..0x3AD].copy_from_slice(&0u32.to_be_bytes()); // STFS
        v[0x3000..0x3003].copy_from_slice(b"ABC");
        let mut hasher = Sha1::new();
        hasher.update(&v[0x3000..0x4000]);
        let digest = hasher.finalize();
        v[0x1000 + 20..0x1000 + 24].copy_from_slice(&END.to_be_bytes());
        v[0x1000 + 0x18..0x1000 + 0x2C].copy_from_slice(&digest);
        v[0x1000 + 0x2C..0x1000 + 0x30].copy_from_slice(&END.to_be_bytes());
        // Entry 0: dir "data" under root.
        let e0 = 0x2000;
        v[e0..e0 + 4].copy_from_slice(b"data");
        v[e0 + 40] = 0x84; // len 4 + dir bit
        v[e0 + 47..e0 + 50].copy_from_slice(&[0, 0, 0]); // start 0
        v[e0 + 50..e0 + 52].copy_from_slice(&0xFFFFu16.to_be_bytes());
        v[e0 + 52..e0 + 56].copy_from_slice(&0u32.to_be_bytes());
        // Entry 1: file "english.mo" under entry 0.
        let e1 = 0x2040;
        v[e1..e1 + 10].copy_from_slice(b"english.mo");
        v[e1 + 40] = 10;
        v[e1 + 47..e1 + 50].copy_from_slice(&[1, 0, 0]); // start block 1
        v[e1 + 50..e1 + 52].copy_from_slice(&0u16.to_be_bytes());
        v[e1 + 52..e1 + 56].copy_from_slice(&3u32.to_be_bytes());
        // Entry 2: orphan (parent 9 never resolves).
        let e2 = 0x2080;
        v[e2..e2 + 10].copy_from_slice(b"orphan.bin");
        v[e2 + 40] = 10;
        v[e2 + 47..e2 + 50].copy_from_slice(&[1, 0, 0]);
        v[e2 + 50..e2 + 52].copy_from_slice(&9u16.to_be_bytes());
        v[e2 + 52..e2 + 56].copy_from_slice(&3u32.to_be_bytes());
        v
    }

    #[test]
    fn stfs_fs_synthetic_index_shapes() {
        let bytes = synthetic_package();
        let fs = StfsFs::load(Arc::from(bytes.into_boxed_slice())).expect("index");
        match fs.lookup("data/english.mo") {
            FsLookup::File(b) => assert_eq!(&b[..], b"ABC"),
            _ => panic!("nested file missing"),
        }
        match fs.lookup("data") {
            FsLookup::Dir(kids) => {
                assert!(kids.iter().any(|k| k.name == "english.mo" && !k.is_dir))
            }
            _ => panic!("dir missing"),
        }
        // Orphaned entry is unreachable, never indexed.
        assert!(matches!(fs.lookup("orphan.bin"), FsLookup::NotFound));
        // Normalization: case, separators, and dots resolve alike.
        for probe in [
            "DATA/ENGLISH.MO",
            "data\\english.mo",
            "/data/english.mo",
            "data/./english.mo",
            "data/sub/../english.mo",
        ] {
            match fs.lookup(probe) {
                FsLookup::File(b) => assert_eq!(&b[..], b"ABC", "probe {}", probe),
                _ => panic!("probe missed: {}", probe),
            }
        }
        // Cached second lookup agrees.
        match fs.lookup("data/english.mo") {
            FsLookup::File(b) => assert_eq!(&b[..], b"ABC"),
            _ => panic!("cache miss"),
        }
    }
}
