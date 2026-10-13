//! Threads, sync primitives, syscalls, XAM services.
//!
//! Guest syscall convention (M4, pending-M6 formal ABI):
//! guest `r0` holds the id at `sc` time.
//! - 0: time in ms (returns value)
//! - 1: exit with code in `r3` (handled by the boot runner)
//! - 2: console putc of low byte of `r3` (returns 0)

use std::collections::{HashMap, VecDeque};
use x360_common::{EmuError, Result};
use x360_cpu::regs::ThreadState;

pub mod boot;
pub mod dispatch;
pub mod imports;
pub mod ordinals;
pub mod variables;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Handle(pub u32);

#[derive(Debug)]
#[allow(dead_code)]
struct Thread {
    state: ThreadState,
    priority: u8,
    alive: bool,
}

#[derive(Debug, Default)]
struct Event {
    signaled: bool,
    waiters: Vec<u32>,
}

/// Kernel state. Owns scheduling and objects.
pub struct Kernel {
    next_handle: u32,
    threads: HashMap<u32, Thread>,
    ready: VecDeque<u32>,
    events: HashMap<u32, Event>,
    pub syscall_count: u64,
    pub unimplemented_syscalls: HashMap<u32, u64>,
    /// Guest console bytes from syscall 2 (putc). Bounded to 1 MB.
    pub console: Vec<u8>,
    /// Bump-allocated guest heap for import backing stores, pool
    /// allocations, and virtual-memory shims. Guests see real zeroed
    /// bytes; `allocs` tracks live ranges for free/query.
    heap_next: u32,
    heap_end: u32,
    allocs: HashMap<u32, u32>,
    /// TLS slots for KeTls* (`None` = free).
    tls: [Option<u32>; 64],
    /// Critical-section states by guest struct address.
    crits: HashMap<u32, CritSec>,
    /// Loaded module facts for RtlImageXexHeaderField / XexGetModule*.
    pub image_base: u32,
    pub image_size: u32,
    pub title_id: u32,
    xex_header: Vec<u8>,
    entry_point_val: u32,
    module_name: String,
    xex_header_addr: u32,
    stack_base: u32,
    stack_size: u32,
    system_flags: u32,
}

/// Single-threaded critical-section state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CritSec {
    owning_thread: Option<u32>,
    recursion: u32,
    spin: u32,
}

/// Guest heap window for emulated allocations (inside the cached
/// mirror, above typical image placement at 0x82000000+).
pub const HEAP_BASE: u32 = 0x8400_0000;
pub const HEAP_END: u32 = 0x9F00_0000;

impl Kernel {
    pub fn new() -> Self {
        Self {
            next_handle: 1,
            threads: HashMap::new(),
            ready: VecDeque::new(),
            events: HashMap::new(),
            syscall_count: 0,
            unimplemented_syscalls: HashMap::new(),
            console: Vec::new(),
            heap_next: HEAP_BASE,
            heap_end: HEAP_END,
            allocs: HashMap::new(),
            tls: [None; 64],
            crits: HashMap::new(),
            image_base: 0,
            image_size: 0,
            title_id: 0,
            xex_header: Vec::new(),
            entry_point_val: 0,
            module_name: String::new(),
            xex_header_addr: 0,
            stack_base: 0,
            stack_size: 0,
            system_flags: 0,
        }
    }

    /// Record loaded-module facts for header-field queries.
    pub fn set_module_info(&mut self, base: u32, size: u32, title_id: u32) {
        self.image_base = base;
        self.image_size = size;
        self.title_id = title_id;
    }

    /// Store the XEX file header (up to `header_size`) plus entry point
    /// and module name for `RtlImageXexHeaderField` / `XexGetModule*`.
    pub fn set_xex_header(&mut self, header: Vec<u8>, entry: u32, module_name: String) {
        self.xex_header = header;
        self.entry_point_val = entry;
        self.module_name = module_name;
    }

    pub fn entry_point(&self) -> u32 {
        self.entry_point_val
    }

    /// Serve an XEX optional-header field from the stored header image.
    /// Returns `None` when the header is absent or the key is unknown.
    /// Layout facts: 8-byte entries at +24, inline when `key & 0xFF`
    /// is 0x00/0x01, else a file offset to the payload. Accepts both
    /// the linked image base and the placed header-copy address,
    /// since games pass the in-memory header pointer.
    pub fn xex_header_field(&self, header_ptr: u32, field: u32) -> Option<u32> {
        if self.xex_header.is_empty() {
            return None;
        }
        // `header_ptr` must be the linked base or our placed copy.
        if header_ptr != self.image_base && header_ptr != self.xex_header_addr {
            return None;
        }
        if self.xex_header.len() < 24 {
            return None;
        }
        let count = u32::from_be_bytes([
            self.xex_header[20],
            self.xex_header[21],
            self.xex_header[22],
            self.xex_header[23],
        ]);
        if count > 64 {
            return None;
        }
        for i in 0..count as usize {
            let off = 24 + i * 8;
            if off + 8 > self.xex_header.len() {
                return None;
            }
            let key = u32::from_be_bytes([
                self.xex_header[off],
                self.xex_header[off + 1],
                self.xex_header[off + 2],
                self.xex_header[off + 3],
            ]);
            let value = u32::from_be_bytes([
                self.xex_header[off + 4],
                self.xex_header[off + 5],
                self.xex_header[off + 6],
                self.xex_header[off + 7],
            ]);
            if key != field {
                continue;
            }
            match key & 0xFF {
                0x00 | 0x01 => return Some(value),
                _ => {
                    // Offset payloads: execution info title id (+0x0C)
                    // is the one games poll most.
                    if key == 0x0004_0006 {
                        let o = value as usize + 0x0C;
                        if o + 4 <= self.xex_header.len() {
                            return Some(u32::from_be_bytes([
                                self.xex_header[o],
                                self.xex_header[o + 1],
                                self.xex_header[o + 2],
                                self.xex_header[o + 3],
                            ]));
                        }
                        return Some(self.title_id);
                    }
                    return Some(value);
                }
            }
        }
        None
    }

    /// Record the guest stack window for `RtlGetStackLimits`.
    pub fn set_stack(&mut self, base: u32, size: u32) {
        self.stack_base = base;
        self.stack_size = size;
    }

    pub fn stack_base(&self) -> u32 {
        self.stack_base
    }

    pub fn stack_size(&self) -> u32 {
        self.stack_size
    }

    /// Place the stored XEX header image in guest memory and return its
    /// address (for module-structure chains). Errors when no header was
    /// recorded.
    pub fn place_xex_header(&mut self, mem: &mut x360_memory::Memory) -> Result<u32> {
        if self.xex_header.is_empty() {
            return Err(EmuError::Other("no XEX header recorded".into()));
        }
        let len = self.xex_header.len() as u32;
        let addr = self.alloc_mem(len, 4)?;
        let bytes = self.xex_header.clone();
        mem.write_bytes(addr, &bytes)?;
        self.xex_header_addr = addr;
        Ok(addr)
    }

    /// Record the XEX system-flags word for privilege queries.
    pub fn set_system_flags(&mut self, flags: u32) {
        self.system_flags = flags;
    }

    /// Allocate at a fixed guest address (for fixed-base virtual-memory
    /// requests inside the heap window). Errors when out of range.
    pub fn alloc_mem_at(&mut self, addr: u32, size: u32) -> Result<u32> {
        if addr < HEAP_BASE || (addr as u64) + (size as u64) > self.heap_end as u64 {
            return Err(EmuError::Other(format!(
                "fixed alloc {:08x}+{:x} outside heap window",
                addr, size
            )));
        }
        if addr + size > self.heap_next {
            self.heap_next = addr + size;
        }
        self.allocs.insert(addr, size);
        Ok(addr)
    }

    // ---- TLS (KeTls*): 64 slots, single-threaded values ----

    pub fn tls_alloc(&mut self) -> Option<u32> {
        for (i, s) in self.tls.iter_mut().enumerate() {
            if s.is_none() {
                *s = Some(0);
                return Some(i as u32);
            }
        }
        None
    }

    pub fn tls_free(&mut self, index: u32) -> bool {
        if (index as usize) < self.tls.len() {
            self.tls[index as usize] = None;
            true
        } else {
            false
        }
    }

    pub fn tls_get(&self, index: u32) -> u32 {
        if (index as usize) < self.tls.len() {
            self.tls[index as usize].unwrap_or(0)
        } else {
            0
        }
    }

    pub fn tls_set(&mut self, index: u32, value: u32) -> bool {
        if (index as usize) < self.tls.len() && self.tls[index as usize].is_some() {
            self.tls[index as usize] = Some(value);
            true
        } else {
            false
        }
    }

    // ---- Critical-section bookkeeping (guest bytes authoritative) ----

    pub(crate) fn crit_insert(&mut self, cs: u32, spin: u8) {
        self.crits.insert(
            cs,
            CritSec {
                owning_thread: None,
                recursion: 0,
                spin: spin as u32,
            },
        );
    }

    pub(crate) fn crit_owned(&mut self, cs: u32, thread: u32) {
        if let Some(c) = self.crits.get_mut(&cs) {
            c.owning_thread = Some(thread);
            c.recursion += 1;
        }
    }

    pub(crate) fn crit_released(&mut self, cs: u32) {
        if let Some(c) = self.crits.get_mut(&cs) {
            c.owning_thread = None;
            c.recursion = 0;
        }
    }

    /// Bump-allocate zeroed guest memory. Real bytes, tracked for
    /// free/query. Never reuses freed ranges (avoids use-after-free).
    pub fn alloc_mem(&mut self, size: u32, align: u32) -> Result<u32> {
        let align = align.max(8);
        if !align.is_power_of_two() {
            return Err(EmuError::Other(format!("alloc align {} invalid", align)));
        }
        let size = size.max(8);
        let base = (self.heap_next + align - 1) & !(align - 1);
        let end = base
            .checked_add(size)
            .ok_or_else(|| EmuError::Other("alloc overflow".into()))?;
        if end > self.heap_end {
            return Err(EmuError::Other(format!(
                "guest heap exhausted (want {} bytes)",
                size
            )));
        }
        self.heap_next = end;
        self.allocs.insert(base, size);
        Ok(base)
    }

    /// Release a tracked range. Memory is left as-is (no reuse).
    pub fn free_mem(&mut self, addr: u32) -> Result<u32> {
        self.allocs.remove(&addr).ok_or_else(|| {
            EmuError::Other(format!("free of untracked guest range {:08x}", addr))
        })?;
        Ok(0)
    }

    /// Size of a tracked range, 0 when unknown.
    pub fn alloc_size(&self, addr: u32) -> u32 {
        self.allocs.get(&addr).copied().unwrap_or(0)
    }

    fn alloc_handle(&mut self) -> Handle {
        let h = Handle(self.next_handle);
        self.next_handle += 1;
        h
    }

    pub fn create_thread(&mut self, entry: u32, priority: u8) -> Handle {
        let h = self.alloc_handle();
        let id = h.0 as usize;
        self.threads.insert(
            h.0,
            Thread {
                state: ThreadState::new(id, entry),
                priority,
                alive: true,
            },
        );
        self.ready.push_back(h.0);
        log::info!(
            "kernel: thread {} entry={:08x} prio={}",
            h.0,
            entry,
            priority
        );
        h
    }

    pub fn create_event(&mut self, initial: bool) -> Handle {
        let h = self.alloc_handle();
        self.events.insert(
            h.0,
            Event {
                signaled: initial,
                waiters: Vec::new(),
            },
        );
        h
    }

    pub fn set_event(&mut self, h: Handle) -> Result<()> {
        let e = self
            .events
            .get_mut(&h.0)
            .ok_or_else(|| EmuError::Other(format!("bad event {}", h.0)))?;
        e.signaled = true;
        e.waiters.clear();
        Ok(())
    }

    pub fn wait_event(&mut self, h: Handle, timeout_ms: Option<u32>) -> Result<bool> {
        let e = self
            .events
            .get_mut(&h.0)
            .ok_or_else(|| EmuError::Other(format!("bad event {}", h.0)))?;
        if e.signaled {
            // Manual-reset stays signaled; auto-reset would clear here.
            return Ok(true);
        }
        // Not signaled: queue a waiter marker so wake-ups are observable.
        // Blocking wait is pending-M6; current semantics are non-blocking
        // poll honoring timeout==Some(0) explicitly.
        e.waiters.push(u32::MAX);
        match timeout_ms {
            Some(0) => Ok(false),
            // None / Some(>0) would block in a full kernel; report non-ready
            // without swallowing the timeout value.
            _ => {
                log::debug!(
                    "kernel: wait_event {} pending (timeout {:?}), queued waiter",
                    h.0,
                    timeout_ms
                );
                Ok(false)
            }
        }
    }

    /// Syscall dispatch. Implemented numbers grow with M6; others are
    /// explicit UnimplementedSyscall, never fake success.
    /// id 1 (exit) is handled by the boot runner, not here.
    pub fn syscall(&mut self, id: u32, args: &[u32]) -> Result<u32> {
        self.syscall_count += 1;
        match id {
            // 0: GetTickCount-style stub with real time base.
            0 => Ok(std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u32)
                .unwrap_or(0)),
            // 2: console putc, low byte of first arg.
            2 => {
                let b = args.first().copied().unwrap_or(0) as u8;
                if self.console.len() < 1024 * 1024 {
                    self.console.push(b);
                }
                Ok(0)
            }
            _ => {
                *self.unimplemented_syscalls.entry(id).or_insert(0) += 1;
                log::warn!("kernel: unimplemented syscall {}", id);
                Err(EmuError::UnimplementedSyscall(id))
            }
        }
    }

    pub fn ready_len(&self) -> usize {
        self.ready.len()
    }
}

impl Default for Kernel {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn thread_and_event() {
        let mut k = Kernel::new();
        let t = k.create_thread(0x8200_1000, 8);
        assert_eq!(k.ready_len(), 1);
        let e = k.create_event(false);
        assert!(!k.wait_event(e, None).unwrap());
        k.set_event(e).unwrap();
        assert!(k.wait_event(e, None).unwrap());
        assert!(!k.unimplemented_syscalls.contains_key(&0));
        let _ = t;
    }
    #[test]
    fn unknown_syscall_is_error() {
        let mut k = Kernel::new();
        assert!(k.syscall(0xFFFF, &[]).is_err());
    }
}
