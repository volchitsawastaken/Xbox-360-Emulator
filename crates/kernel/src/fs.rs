//! Guest file-system path model and open-file table.
//!
//! Path/device facts ported from the BSD-licensed Xenia
//! `xboxkrnl_io.cc` (`NtCreateFile` root handling, `CreateOptions`,
//! `IsValidPath` call sites), `kernel.h` (`X_OBJECT_ATTRIBUTES`,
//! `X_ANSI_STRING`), `vfs/entry.h` (`FileDisposition`, `FileAction`),
//! `vfs/virtual_file_system.cc` (`OpenFile` decision table,
//! case-insensitive child lookup), `xfile.cc` (`Read` position/EOF
//! semantics), and `xbox.h` (NTSTATUS values) — facts only, all code
//! original.

use std::collections::HashMap;
use std::sync::Arc;

use x360_common::{EmuError, Result};

// NTSTATUS file codes (reference `xbox.h`).
pub const STATUS_END_OF_FILE: u32 = 0xC000_0011;
pub const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
pub const STATUS_OBJECT_NAME_INVALID: u32 = 0xC000_0033;
pub const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;
pub const STATUS_OBJECT_NAME_COLLISION: u32 = 0xC000_0035;
pub const STATUS_OBJECT_PATH_NOT_FOUND: u32 = 0xC000_003A;
pub const STATUS_FILE_IS_A_DIRECTORY: u32 = 0xC000_00BA;
pub const STATUS_NOT_A_DIRECTORY: u32 = 0xC000_0103;
pub const STATUS_NO_SUCH_FILE: u32 = 0xC000_000F;

// FileAction (reference `vfs/entry.h`): reported in IOSB information.
pub const ACTION_SUPERSEDED: u32 = 0;
pub const ACTION_OPENED: u32 = 1;
pub const ACTION_CREATED: u32 = 2;
pub const ACTION_OVERWRITTEN: u32 = 3;

// FileDisposition (reference `vfs/entry.h`): creation_disposition values.
pub const DISP_SUPERSEDE: u32 = 0;
pub const DISP_OPEN: u32 = 1;
pub const DISP_CREATE: u32 = 2;
pub const DISP_OPEN_IF: u32 = 3;
pub const DISP_OVERWRITE: u32 = 4;
pub const DISP_OVERWRITE_IF: u32 = 5;

// CreateOptions bits (reference `xboxkrnl_io.cc`).
pub const OPT_DIRECTORY_FILE: u32 = 0x0000_0001;
pub const OPT_SEQUENTIAL_ONLY: u32 = 0x0000_0004;
pub const OPT_SYNC_ALERT: u32 = 0x0000_0010;
pub const OPT_SYNC_NONALERT: u32 = 0x0000_0020;
pub const OPT_NON_DIRECTORY_FILE: u32 = 0x0000_0040;
pub const OPT_RANDOM_ACCESS: u32 = 0x0000_0800;

// Write-access bits (reference `base/filesystem.h` `FileAccess`).
pub const ACCESS_GENERIC_WRITE: u32 = 0x4000_0000;
pub const ACCESS_WRITE_DATA: u32 = 0x0000_0002;
pub const ACCESS_APPEND_DATA: u32 = 0x0000_0004;

/// `ObDosDevices` root: path is absolute (reference `xboxkrnl_io.cc`).
pub const ROOT_DOS_DEVICES: u32 = 0xFFFF_FFFD;
/// Invalid handle value returned in `handle_out` on failure.
pub const INVALID_HANDLE_VALUE: u32 = 0xFFFF_FFFF;

/// One directory entry for listings.
#[derive(Debug, Clone)]
pub struct FsDirEntry {
    pub name: String,
    pub is_dir: bool,
    pub len: u64,
}

/// Backend lookup result. Paths are normalized lowercase
/// `/`-separated, relative to the game root (`""` = root).
#[derive(Debug, Clone)]
pub enum FsLookup {
    File(Arc<[u8]>),
    Dir(Vec<FsDirEntry>),
    NotFound,
}

/// Source of game file bytes (STFS package, host dir, ...).
/// Object-safe; lookups return owned Arcs so no borrows escape.
pub trait GuestFs: Send + Sync {
    fn lookup(&self, path: &str) -> FsLookup;
}

/// An open guest file or directory enumeration.
#[derive(Debug, Clone)]
pub struct OpenFile {
    pub path: String,
    pub data: Option<Arc<[u8]>>,
    pub pos: u64,
    pub is_dir: bool,
    pub synchronous: bool,
}

/// Normalize a guest path to lowercase `/`-separated form relative
/// to the game root (`""` = root). `base` is the opener's directory
/// for root-relative opens. Returns the NTSTATUS on invalid input.
///
/// Device facts (reference `emulator.cc`, `virtual_file_system.cc`):
/// `game:`/`d:` address the running title; `\Device\Harddisk0\...`,
/// `\Device\Package_0`, `\Device\Cdrom0` roots do too. Everything
/// else is a genuine PATH_NOT_FOUND until backed.
pub fn normalize_guest_path(raw: &[u8], base: Option<&str>) -> std::result::Result<String, u32> {
    // Reference `IsValidPath` (non-pattern): no control/high bytes,
    // none of `" + , < > |`, no `*`/`?`.
    for b in raw {
        if *b <= 31
            || *b >= 127
            || matches!(*b, b'"' | b'+' | b',' | b'<' | b'>' | b'|' | b'*' | b'?')
        {
            return Err(STATUS_OBJECT_NAME_INVALID);
        }
    }
    let s = String::from_utf8_lossy(raw);
    let t = s.trim_matches(|c: char| c.is_whitespace()).to_string();
    let lower = t.to_ascii_lowercase();

    // Absolute (has a device prefix) or relative to `base`.
    let rest: &str;
    if let Some(stripped) = lower.strip_prefix("\\device\\") {
        // `\Device\...` form: first component names the device.
        let (dev, tail) = match stripped.find('\\') {
            Some(i) => (&stripped[..i], &stripped[i + 1..]),
            None => (stripped, ""),
        };
        match dev {
            "harddisk0" => {
                // `\Device\Harddisk0\Partition1\...` is the title volume
                // (reference `LaunchPath`); bare `\Device\Harddisk0`
                // (NullDevice: Partition0/Cache) is not game content.
                if let Some(after) = tail.strip_prefix("partition1") {
                    rest = after.trim_start_matches('\\');
                } else {
                    return Err(STATUS_OBJECT_PATH_NOT_FOUND);
                }
            }
            "package_0" | "cdrom0" => {
                rest = tail;
            }
            _ => return Err(STATUS_OBJECT_PATH_NOT_FOUND),
        }
    } else if let Some(colon) = lower.find(':') {
        // `drive:` form; slashes must not precede the colon.
        if lower[..colon].contains(['/', '\\']) {
            // Not a device at all: treat as relative below.
            rest = &lower;
            return join_and_resolve(base, rest);
        }
        let (dev, tail) = (&lower[..colon], &lower[colon + 1..]);
        match dev {
            "game" | "d" => {
                rest = tail.trim_start_matches(['/', '\\']);
            }
            _ => return Err(STATUS_OBJECT_PATH_NOT_FOUND),
        }
    } else {
        rest = &lower;
        return join_and_resolve(base, rest);
    }
    // Absolute: resolve components without a base.
    Ok(resolve_components(rest))
}

/// Join an optional base with a relative path, then resolve.
fn join_and_resolve(base: Option<&str>, rel: &str) -> std::result::Result<String, u32> {
    let mut full = String::new();
    if let Some(b) = base {
        if !b.is_empty() {
            full.push_str(b);
            full.push('/');
        }
    }
    full.push_str(rel);
    Ok(resolve_components(&full))
}

/// Separators to `/`, collapse repeats, resolve `.`/`..`
/// (never above root; reference `canonicalize_guest_path`).
fn resolve_components(path: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for comp in path.split(['/', '\\']) {
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

/// What a normalized path resolved to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LookupKind {
    File,
    Dir,
    Missing,
}

/// Open decision table (reference `virtual_file_system.cc`
/// `OpenFile`). Write/overwrite/create intents on this read-only
/// backend are ACCESS_DENIED (reference create-fails);
/// `kCreate` on an existing name is COLLISION; `kOpen`/`kOverwrite`
/// on a missing name is NOT_FOUND. Returns the IOSB action.
pub fn open_action(
    disposition: u32,
    target: LookupKind,
    want_directory: bool,
    want_non_directory: bool,
) -> std::result::Result<u32, u32> {
    match target {
        LookupKind::Dir if want_non_directory => Err(STATUS_FILE_IS_A_DIRECTORY),
        LookupKind::File if want_directory => {
            // DIRECTORY_FILE for a real file: not a directory.
            Err(STATUS_NOT_A_DIRECTORY)
        }
        LookupKind::File | LookupKind::Dir => match disposition {
            DISP_OPEN | DISP_OPEN_IF => Ok(ACTION_OPENED),
            DISP_CREATE => Err(STATUS_OBJECT_NAME_COLLISION),
            DISP_OVERWRITE | DISP_OVERWRITE_IF | DISP_SUPERSEDE => Err(STATUS_ACCESS_DENIED),
            _ => Err(crate::dispatch::STATUS_INVALID_PARAMETER),
        },
        LookupKind::Missing => match disposition {
            DISP_OPEN | DISP_OVERWRITE => Err(STATUS_OBJECT_NAME_NOT_FOUND),
            DISP_CREATE | DISP_OPEN_IF | DISP_OVERWRITE_IF | DISP_SUPERSEDE => {
                Err(STATUS_ACCESS_DENIED)
            }
            _ => Err(crate::dispatch::STATUS_INVALID_PARAMETER),
        },
    }
}

/// Read bytes from an open file (reference `xfile.cc` `Read`).
/// `offset`: None or u64::MAX = current position; an explicit value
/// (including nonzero) seeks first — except explicit 0, which the
/// reference quirk leaves un-seeked. Returns (start, len, status).
pub fn file_read_window(
    data_len: u64,
    pos: u64,
    want: u64,
    offset: Option<u64>,
) -> (u64, usize, u32) {
    if want == 0 {
        return (pos, 0, crate::dispatch::STATUS_SUCCESS);
    }
    let mut p = pos;
    if let Some(off) = offset {
        if off != u64::MAX && off != 0 {
            p = off;
        }
    }
    if p >= data_len {
        return (p, 0, STATUS_END_OF_FILE);
    }
    let avail = data_len - p;
    let n = avail.min(want) as usize;
    (p, n, crate::dispatch::STATUS_SUCCESS)
}

/// Open-file table helpers owned by [`crate::Kernel`].
#[derive(Debug, Default)]
pub struct FileTable {
    files: HashMap<u32, OpenFile>,
}

impl FileTable {
    pub fn insert(&mut self, handle: u32, file: OpenFile) {
        self.files.insert(handle, file);
    }

    pub fn get(&self, handle: u32) -> Option<&OpenFile> {
        self.files.get(&handle)
    }

    pub fn get_mut(&mut self, handle: u32) -> Option<&mut OpenFile> {
        self.files.get_mut(&handle)
    }

    pub fn remove(&mut self, handle: u32) -> bool {
        self.files.remove(&handle).is_some()
    }

    pub fn contains(&self, handle: u32) -> bool {
        self.files.contains_key(&handle)
    }
}

/// Stack-argument reader (PPC ABI: first 8 words in r3-r10, the rest
/// at [r1+8], [r1+12], ...). `i` = 0-based stack-arg index.
pub fn stack_arg(mem: &x360_memory::Memory, r1: u32, i: u32) -> Result<u32> {
    mem.read_u32(r1.wrapping_add(8).wrapping_add(i * 4))
        .map_err(|e| EmuError::Other(format!("guest stack arg {} unreadable: {}", i, e)))
}
