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
    /// NT handle-tracked sync objects (reference `xobject.h` object
    /// table; handles share the kernel handle namespace).
    pub nt_events: HashMap<u32, NtEvent>,
    pub nt_semaphores: HashMap<u32, NtSemaphore>,
    pub nt_mutants: HashMap<u32, NtMutant>,
    pub nt_timers: HashMap<u32, NtTimer>,
    pub nt_threads: HashMap<u32, NtThread>,
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

/// NT handle-tracked event (reference `xevent.cc`: manual vs auto-reset).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NtEvent {
    pub manual: bool,
    pub signaled: bool,
    pub guest_ptr: u32,
}

/// NT semaphore (reference `xsemaphore.cc`: counted with limit).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NtSemaphore {
    pub count: i32,
    pub limit: i32,
    pub guest_ptr: u32,
}

/// NT mutant/mutex (reference `xmutant.cc`: owned with recursion).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NtMutant {
    pub owner: Option<u32>,
    pub recursion: u32,
    pub guest_ptr: u32,
}

/// NT timer (reference `xtimer.cc`: notification vs synchronization).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NtTimer {
    pub timer_type: u32,
    pub signaled: bool,
    pub guest_ptr: u32,
}

/// NT thread (reference `xthread.cc` / `X_KTHREAD` in `xthread.h`).
/// Single-threaded runner tracks creation state only; created threads
/// are not yet scheduled (documented M6 gap, never silent).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NtThread {
    pub stack_base: u32,
    pub stack_size: u32,
    pub start_addr: u32,
    pub start_context: u32,
    pub suspend_count: u32,
    pub exited: bool,
    pub exit_code: u32,
    pub thread_id: u32,
    pub kthread_ptr: u32,
    pub affinity: u32,
    pub active_cpu: u8,
    pub priority: i32,
    pub boost_disabled: u8,
}

/// Single-threaded critical-section state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CritSec {
    owning_thread: Option<u32>,
    recursion: u32,
    spin: u32,
}

/// Guest heap window for emulated allocations. Starts low (above the
/// null page), mirroring the reference/Xenon convention where normal
/// user allocations come from low virtual address ranges — game logic
/// here derives search keys from pointer high-halves, so the base is
/// load-bearing, not arbitrary.
pub const HEAP_BASE: u32 = 0x0100_0000;
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
            nt_events: HashMap::new(),
            nt_semaphores: HashMap::new(),
            nt_mutants: HashMap::new(),
            nt_timers: HashMap::new(),
            nt_threads: HashMap::new(),
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

    /// Sorted (base, size) snapshot of live ranges, for the debugger
    /// and boot forensics (e.g., which region owns a fault address).
    pub fn heap_map(&self) -> Vec<(u32, u32)> {
        let mut v: Vec<_> = self.allocs.iter().map(|(a, s)| (*a, *s)).collect();
        v.sort();
        v
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

    // ---- NT handle-tracked sync objects (reference `xevent.cc`,
    // `xsemaphore.cc`, `xmutant.cc`, `xtimer.cc`; facts only) ----
    //
    // Every object owns a real guest backing struct (dispatch-header
    // layouts from `xobject.h` / `xthread.h` / `xevent.h`) so
    // `ObReferenceObjectByHandle` returns a usable pointer, exactly
    // like the reference. Host state is authoritative; guest bytes
    // are mirrored on every mutation.

    /// Write an `X_DISPATCH_HEADER` (16 bytes): type, signal state,
    /// zeroed wait list.
    fn write_dispatch_header(
        mem: &mut x360_memory::Memory,
        ptr: u32,
        type_byte: u8,
        signal_state: u32,
    ) -> Result<()> {
        let mut hdr = [0u8; 16];
        hdr[0] = type_byte;
        hdr[4..8].copy_from_slice(&signal_state.to_be_bytes());
        mem.write_bytes(ptr, &hdr)
    }

    /// Create an NT event. `event_type` 0 = notification (manual-reset),
    /// nonzero = synchronization (auto-reset). Returns the new handle.
    pub fn nt_create_event(
        &mut self,
        mem: &mut x360_memory::Memory,
        event_type: u32,
        initial: bool,
    ) -> Result<u32> {
        let guest = self.alloc_mem(0x10, 8)?;
        let type_byte = if event_type == 0 { 0u8 } else { 1u8 };
        Self::write_dispatch_header(mem, guest, type_byte, u32::from(initial))?;
        let h = self.alloc_handle().0;
        self.nt_events.insert(
            h,
            NtEvent {
                manual: event_type == 0,
                signaled: initial,
                guest_ptr: guest,
            },
        );
        Ok(h)
    }

    pub fn nt_set_event(&mut self, handle: u32) -> Result<i32> {
        let e = self
            .nt_events
            .get_mut(&handle)
            .ok_or_else(|| EmuError::Other(format!("bad NT event {:08x}", handle)))?;
        let prev = i32::from(e.signaled);
        e.signaled = true;
        Ok(prev)
    }

    pub fn nt_clear_event(&mut self, handle: u32) -> Result<()> {
        let e = self
            .nt_events
            .get_mut(&handle)
            .ok_or_else(|| EmuError::Other(format!("bad NT event {:08x}", handle)))?;
        e.signaled = false;
        Ok(())
    }

    /// Pulse: report previous state and reset to nonsignaled (reference
    /// `XEvent::Pulse`; waiting threads would be released — with no
    /// threads blocked, this is set-then-clear).
    pub fn nt_pulse_event(&mut self, handle: u32) -> Result<i32> {
        let e = self
            .nt_events
            .get_mut(&handle)
            .ok_or_else(|| EmuError::Other(format!("bad NT event {:08x}", handle)))?;
        let prev = i32::from(e.signaled);
        e.signaled = false;
        Ok(prev)
    }

    /// Create an NT semaphore. Validates `0 <= count <= limit > 0`
    /// (reference `XSemaphore::Initialize` fails otherwise).
    pub fn nt_create_semaphore(
        &mut self,
        mem: &mut x360_memory::Memory,
        count: i32,
        limit: i32,
    ) -> Result<u32> {
        if limit <= 0 || count < 0 || count > limit {
            return Err(EmuError::Other(format!(
                "bad semaphore count {} limit {}",
                count, limit
            )));
        }
        let guest = self.alloc_mem(0x14, 8)?;
        Self::write_dispatch_header(mem, guest, 5, count as u32)?;
        mem.write_u32(guest + 0x10, limit as u32)?;
        let h = self.alloc_handle().0;
        self.nt_semaphores.insert(
            h,
            NtSemaphore {
                count,
                limit,
                guest_ptr: guest,
            },
        );
        Ok(h)
    }

    /// Release (increment) an NT semaphore. Returns the previous count
    /// (reference `XSemaphore::ReleaseSemaphore` fails past the limit).
    pub fn nt_release_semaphore(&mut self, handle: u32, release: i32) -> Result<i32> {
        let s = self
            .nt_semaphores
            .get_mut(&handle)
            .ok_or_else(|| EmuError::Other(format!("bad semaphore {:08x}", handle)))?;
        if release < 0 || s.count + release > s.limit {
            return Err(EmuError::Other(format!(
                "semaphore {:08x} release {} exceeds limit (count {} limit {})",
                handle, release, s.count, s.limit
            )));
        }
        let prev = s.count;
        s.count += release;
        Ok(prev)
    }

    /// Create an NT mutant. When `initial_owner`, the calling thread
    /// owns it with recursion 1 (reference `XMutant::Initialize`).
    /// The guest `X_KMUTANT` (0x20) owner field points at the owner's
    /// KTHREAD, or 0 for the boot thread (which has no NT object).
    pub fn nt_create_mutant(
        &mut self,
        mem: &mut x360_memory::Memory,
        initial_owner: bool,
        owner_thread: u32,
    ) -> Result<u32> {
        let guest = self.alloc_mem(0x20, 8)?;
        let owner_kthread = if initial_owner {
            self.kthread_of_thread_id(owner_thread)
        } else {
            0
        };
        // Header type 2 (MutantObject); signaled iff unowned.
        Self::write_dispatch_header(mem, guest, 2, if initial_owner { 0 } else { 1 })?;
        mem.write_u32(guest + 0x18, owner_kthread)?;
        mem.write_u8(guest + 0x1C, 0)?;
        let h = self.alloc_handle().0;
        self.nt_mutants.insert(
            h,
            NtMutant {
                owner: if initial_owner {
                    Some(owner_thread)
                } else {
                    None
                },
                recursion: if initial_owner { 1 } else { 0 },
                guest_ptr: guest,
            },
        );
        Ok(h)
    }

    /// Release an NT mutant owned by `thread`. Returns without changing
    /// ownership held by another thread (caller gets MUTANT_NOT_OWNED).
    pub fn nt_release_mutant(&mut self, handle: u32, thread: u32) -> Result<()> {
        let m = self
            .nt_mutants
            .get_mut(&handle)
            .ok_or_else(|| EmuError::Other(format!("bad mutant {:08x}", handle)))?;
        match m.owner {
            Some(o) if o == thread => {
                if m.recursion > 1 {
                    m.recursion -= 1;
                } else {
                    m.recursion = 0;
                    m.owner = None;
                }
                Ok(())
            }
            _ => Err(EmuError::Other(format!(
                "mutant {:08x} not owned by thread {}",
                handle, thread
            ))),
        }
    }

    /// Create an NT timer (0 = notification, 1 = synchronization).
    pub fn nt_create_timer(
        &mut self,
        mem: &mut x360_memory::Memory,
        timer_type: u32,
    ) -> Result<u32> {
        let guest = self.alloc_mem(0x28, 8)?;
        let type_byte = if timer_type == 0 { 8u8 } else { 9u8 };
        Self::write_dispatch_header(mem, guest, type_byte, 0)?;
        let h = self.alloc_handle().0;
        self.nt_timers.insert(
            h,
            NtTimer {
                timer_type,
                signaled: false,
                guest_ptr: guest,
            },
        );
        Ok(h)
    }

    /// KTHREAD address for an NT thread id, 0 when unknown (e.g. the
    /// boot thread, which has no NT thread object).
    pub fn kthread_of_thread_id(&self, thread_id: u32) -> u32 {
        self.nt_threads
            .values()
            .find(|t| t.thread_id == thread_id)
            .map(|t| t.kthread_ptr)
            .unwrap_or(0)
    }

    /// Guest object pointer backing a handle (reference
    /// `XObject::guest_object()`), for `ObReferenceObjectByHandle`.
    pub fn nt_guest_object(&self, handle: u32) -> Option<u32> {
        if let Some(e) = self.nt_events.get(&handle) {
            return Some(e.guest_ptr);
        }
        if let Some(s) = self.nt_semaphores.get(&handle) {
            return Some(s.guest_ptr);
        }
        if let Some(m) = self.nt_mutants.get(&handle) {
            return Some(m.guest_ptr);
        }
        if let Some(t) = self.nt_timers.get(&handle) {
            return Some(t.guest_ptr);
        }
        if let Some(th) = self.nt_threads.get(&handle) {
            return Some(th.kthread_ptr);
        }
        None
    }

    /// Resolve a guest object pointer back to its handle (for the
    /// `Ke*` pointer-taking APIs). Returns (handle, kind) with kind
    /// in {"event","semaphore","mutant","timer","thread"}.
    pub fn nt_handle_of_guest(&self, ptr: u32) -> Option<(u32, &'static str)> {
        for (h, e) in &self.nt_events {
            if e.guest_ptr == ptr {
                return Some((*h, "event"));
            }
        }
        for (h, s) in &self.nt_semaphores {
            if s.guest_ptr == ptr {
                return Some((*h, "semaphore"));
            }
        }
        for (h, m) in &self.nt_mutants {
            if m.guest_ptr == ptr {
                return Some((*h, "mutant"));
            }
        }
        for (h, t) in &self.nt_timers {
            if t.guest_ptr == ptr {
                return Some((*h, "timer"));
            }
        }
        for (h, th) in &self.nt_threads {
            if th.kthread_ptr == ptr {
                return Some((*h, "thread"));
            }
        }
        None
    }

    /// Single-object wait poll for the boot runner (single-threaded):
    /// acquire when signaled, else report not-ready without blocking.
    /// Returns true when the wait completes (object acquired).
    pub fn nt_wait_single(&mut self, handle: u32, thread: u32) -> Result<bool> {
        if let Some(e) = self.nt_events.get_mut(&handle) {
            if e.signaled {
                if !e.manual {
                    e.signaled = false;
                }
                return Ok(true);
            }
            return Ok(false);
        }
        if let Some(s) = self.nt_semaphores.get_mut(&handle) {
            if s.count > 0 {
                s.count -= 1;
                return Ok(true);
            }
            return Ok(false);
        }
        if let Some(m) = self.nt_mutants.get_mut(&handle) {
            match m.owner {
                None => {
                    m.owner = Some(thread);
                    m.recursion = 1;
                    return Ok(true);
                }
                Some(o) if o == thread => {
                    m.recursion += 1;
                    return Ok(true);
                }
                _ => return Ok(false),
            }
        }
        if let Some(t) = self.nt_timers.get(&handle) {
            return Ok(t.signaled);
        }
        if let Some(th) = self.nt_threads.get(&handle) {
            // Waiting on a thread completes when it exits.
            return Ok(th.exited);
        }
        Err(EmuError::Other(format!("bad wait handle {:08x}", handle)))
    }

    /// Create an NT thread (reference `ExCreateThread` /
    /// `xthread.cc`). Allocates a real zeroed stack plus a 0x160-byte
    /// `X_KTHREAD` block (field offsets from `xthread.h`), tracks the
    /// start address/context, and returns (handle, thread_id,
    /// kthread_ptr). Created threads are not yet scheduled — the boot
    /// runner stays on the initial thread (explicit M6 gap).
    pub fn ex_create_thread(
        &mut self,
        mem: &mut x360_memory::Memory,
        stack_size: u32,
        start_addr: u32,
        start_context: u32,
        flags: u32,
    ) -> Result<(u32, u32, u32)> {
        // Reference: stack 0 inherits the process default; align to 4K
        // pages with a 16K minimum.
        let mut actual = if stack_size == 0 {
            0x1_0000
        } else {
            stack_size
        };
        actual = actual.div_ceil(4096) * 4096;
        actual = actual.max(0x4000);
        let stack_base = self.alloc_mem(actual, 4096)?;
        mem.write_bytes(stack_base, &vec![0u8; actual as usize])?;
        let kthread = self.alloc_mem(0x160, 8)?;
        mem.write_bytes(kthread, &vec![0u8; 0x160])?;
        let handle = self.alloc_handle().0;
        let thread_id = self.alloc_handle().0;
        let suspended = flags & 0x0000_0001 != 0;
        // X_KTHREAD fields (reference `xthread.h` offsets).
        mem.write_u32(kthread + 0x5C, stack_base.wrapping_add(actual))?;
        mem.write_u32(kthread + 0x60, stack_base)?;
        mem.write_u32(kthread + 0xD0, stack_base)?;
        mem.write_u8(kthread + 0x6C, if suspended { 0 } else { 1 })?;
        mem.write_u8(kthread + 0x70, 8)?;
        mem.write_u8(kthread + 0xBC, if suspended { 1 } else { 0 })?;
        mem.write_u8(kthread + 0xB9, 8)?;
        mem.write_u8(kthread + 0xBB, 0)?;
        mem.write_u8(kthread + 0xBF, 0)?;
        self.nt_threads.insert(
            handle,
            NtThread {
                stack_base,
                stack_size: actual,
                start_addr,
                start_context,
                suspend_count: if suspended { 1 } else { 0 },
                exited: false,
                exit_code: 0,
                thread_id,
                kthread_ptr: kthread,
                affinity: 0x3F,
                active_cpu: 0,
                priority: 8,
                boost_disabled: 0,
            },
        );
        log::info!(
            "kernel: thread created handle={:08x} id={} start={:08x} ctx={:08x} stack={:08x}+{:x} flags={:08x}",
            handle,
            thread_id,
            start_addr,
            start_context,
            stack_base,
            actual,
            flags
        );
        Ok((handle, thread_id, kthread))
    }

    /// Resume an NT thread. Returns the previous suspend count
    /// (reference `NtResumeThread` / `XThread::Resume`).
    pub fn nt_resume_thread(&mut self, mem: &mut x360_memory::Memory, handle: u32) -> Result<u32> {
        let th = self
            .nt_threads
            .get_mut(&handle)
            .ok_or_else(|| EmuError::Other(format!("bad thread {:08x}", handle)))?;
        if th.exited {
            return Err(EmuError::Other(format!("thread {:08x} exited", handle)));
        }
        let prev = th.suspend_count;
        if prev > 0 {
            th.suspend_count -= 1;
            let kthread = th.kthread_ptr;
            let running = th.suspend_count == 0;
            // Keep the guest KTHREAD in step (offsets from `xthread.h`).
            let _ = mem.write_u8(kthread + 0xBC, th.suspend_count.min(255) as u8);
            if running {
                let _ = mem.write_u8(kthread + 0x6C, 1);
            }
            if running {
                log::info!(
                    "kernel: thread {:08x} resumed (now runnable; still unscheduled)",
                    handle
                );
            }
        }
        Ok(prev)
    }

    /// Suspend an NT thread. Returns the previous suspend count.
    pub fn nt_suspend_thread(&mut self, mem: &mut x360_memory::Memory, handle: u32) -> Result<u32> {
        let th = self
            .nt_threads
            .get_mut(&handle)
            .ok_or_else(|| EmuError::Other(format!("bad thread {:08x}", handle)))?;
        let prev = th.suspend_count;
        th.suspend_count += 1;
        let _ = mem.write_u8(th.kthread_ptr + 0xBC, th.suspend_count.min(255) as u8);
        let _ = mem.write_u8(th.kthread_ptr + 0x6C, 5);
        Ok(prev)
    }

    /// Terminate the calling thread. When `thread` matches a tracked
    /// NT thread, mark it exited; the initial boot thread (no NT
    /// object) maps to process exit and reports it via `Ok(true)`.
    pub fn ex_terminate_thread(&mut self, thread: u32, exit_code: u32) -> Result<bool> {
        for th in self.nt_threads.values_mut() {
            if th.thread_id == thread {
                th.exited = true;
                th.exit_code = exit_code;
                return Ok(false);
            }
        }
        // No NT object for the caller: this is the initial thread.
        Ok(true)
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
