//! Debugger backed by real emulator state.

use std::collections::{HashSet, VecDeque};
use x360_common::Result;
use x360_cpu::{decode::disasm, regs::ThreadState};
use x360_memory::Memory;

/// Default number of instruction events retained by [`TraceBuffer`].
pub const DEFAULT_TRACE_CAPACITY: usize = 1024;
/// Default number of syscall entries retained by [`SyscallLog`].
pub const DEFAULT_SYSCALL_CAPACITY: usize = 256;

/// One traced instruction fetch: program counter, raw word fetched from
/// guest memory, and the disassembly of that word from the real decoder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceEvent {
    pub pc: u32,
    pub word: u32,
    pub disasm: String,
}

/// Fixed-capacity ring buffer of recent instruction fetches.
///
/// Overwrite-oldest-on-full: when the buffer already holds `capacity`
/// events, [`TraceBuffer::push`] discards the oldest event before appending
/// the new one, so iteration order is always oldest-first. A capacity of
/// zero retains nothing and `push` becomes a no-op.
#[derive(Debug, Clone)]
pub struct TraceBuffer {
    events: VecDeque<TraceEvent>,
    capacity: usize,
}

impl TraceBuffer {
    pub fn new(capacity: usize) -> Self {
        Self {
            events: VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn len(&self) -> usize {
        self.events.len()
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Record one fetch at `pc` with raw `word`, disassembling the word
    /// with the real CPU decoder.
    pub fn push(&mut self, pc: u32, word: u32) {
        if self.capacity == 0 {
            return;
        }
        if self.events.len() >= self.capacity {
            self.events.pop_front();
        }
        let disasm = disasm(word);
        self.events.push_back(TraceEvent { pc, word, disasm });
    }

    /// Events oldest-first.
    pub fn iter(&self) -> std::collections::vec_deque::Iter<'_, TraceEvent> {
        self.events.iter()
    }

    pub fn clear(&mut self) {
        self.events.clear();
    }
}

impl Default for TraceBuffer {
    fn default() -> Self {
        Self::new(DEFAULT_TRACE_CAPACITY)
    }
}

/// One watched guest-memory range: half-open interval `[addr, addr + len)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WatchedRange {
    pub addr: u32,
    pub len: u32,
}

/// List of watched guest-memory ranges.
///
/// Ranges are half-open `[addr, addr + len)`, so a probe that starts exactly
/// where a range ends (or ends exactly where a range starts) is adjacent and
/// does not overlap. Zero-length ranges and probes never overlap anything.
#[derive(Debug, Clone, Default)]
pub struct MemWatch {
    ranges: Vec<WatchedRange>,
}

impl MemWatch {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.ranges.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    pub fn ranges(&self) -> &[WatchedRange] {
        &self.ranges
    }

    /// Watch the half-open range `[addr, addr + len)`.
    pub fn watch(&mut self, addr: u32, len: u32) {
        self.ranges.push(WatchedRange { addr, len });
    }

    /// Remove every watched range that starts at `addr`.
    pub fn unwatch(&mut self, addr: u32) {
        self.ranges.retain(|r| r.addr != addr);
    }

    /// Report whether the half-open probe `[addr, addr + len)` overlaps any
    /// watched range.
    pub fn check(&self, addr: u32, len: u32) -> bool {
        if len == 0 {
            return false;
        }
        let probe_start = addr as u64;
        let probe_end = probe_start + len as u64;
        self.ranges.iter().any(|r| {
            if r.len == 0 {
                return false;
            }
            let start = r.addr as u64;
            let end = start + r.len as u64;
            probe_start.max(start) < probe_end.min(end)
        })
    }

    pub fn clear(&mut self) {
        self.ranges.clear();
    }
}

/// One recorded supervisor call: service `id` and the `pc` that issued it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyscallEntry {
    pub id: u32,
    pub pc: u32,
}

/// Bounded log of recent supervisor calls.
///
/// Like [`TraceBuffer`], this is a ring: once `capacity` entries are held,
/// [`SyscallLog::record`] discards the oldest entry before appending.
/// A capacity of zero retains nothing.
#[derive(Debug, Clone)]
pub struct SyscallLog {
    entries: VecDeque<SyscallEntry>,
    capacity: usize,
}

impl SyscallLog {
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Number of entries currently held.
    pub fn count(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Record a call of service `id` issued from `pc`.
    pub fn record(&mut self, id: u32, pc: u32) {
        if self.capacity == 0 {
            return;
        }
        if self.entries.len() >= self.capacity {
            self.entries.pop_front();
        }
        self.entries.push_back(SyscallEntry { id, pc });
    }

    /// The last `n` entries, oldest-first. Returns everything held when
    /// `n` exceeds the entry count; empty when `n` is zero.
    pub fn recent(&self, n: usize) -> Vec<SyscallEntry> {
        let skip = self.entries.len().saturating_sub(n);
        self.entries.iter().skip(skip).copied().collect()
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

impl Default for SyscallLog {
    fn default() -> Self {
        Self::new(DEFAULT_SYSCALL_CAPACITY)
    }
}

pub struct Debugger {
    breakpoints: HashSet<u32>,
    pub trace_syscalls: bool,
    pub trace_gpu: bool,
    pub trace_mem: bool,
    pub trace: TraceBuffer,
    pub mem_watch: MemWatch,
    pub syscall_log: SyscallLog,
}

impl Debugger {
    pub fn new() -> Self {
        Self {
            breakpoints: HashSet::new(),
            trace_syscalls: true,
            trace_gpu: false,
            trace_mem: false,
            trace: TraceBuffer::default(),
            mem_watch: MemWatch::default(),
            syscall_log: SyscallLog::default(),
        }
    }

    pub fn add_breakpoint(&mut self, addr: u32) {
        self.breakpoints.insert(addr & !3);
    }
    pub fn remove_breakpoint(&mut self, addr: u32) {
        self.breakpoints.remove(&(addr & !3));
    }
    pub fn is_breakpoint(&self, addr: u32) -> bool {
        self.breakpoints.contains(&(addr & !3))
    }

    pub fn disasm_at(&self, mem: &Memory, addr: u32, count: usize) -> Vec<String> {
        let mut out = Vec::new();
        for i in 0..count {
            let a = addr.wrapping_add(i as u32 * 4);
            match mem.read_u32(a) {
                Ok(w) => out.push(format!("{:08x}: {}", a, disasm(w))),
                Err(e) => out.push(format!("{:08x}: <fault {}>", a, e)),
            }
        }
        out
    }

    pub fn regs(&self, t: &ThreadState) -> Vec<String> {
        let mut v = Vec::new();
        for i in 0..32 {
            v.push(format!("r{:02}={:08x}", i, t.gpr[i]));
        }
        v.push(format!(
            "pc={:08x} lr={:08x} ctr={:08x} cr={:08x} xer={:08x}",
            t.pc, t.lr, t.ctr, t.cr.0, t.xer.0
        ));
        v
    }

    pub fn dump_mem(&self, mem: &Memory, addr: u32, len: usize) -> Result<Vec<u8>> {
        Ok(mem.read_bytes(addr, len)?.to_vec())
    }

    /// Inspect-only snapshot of the tracing instruments: one formatted line
    /// per trace event (oldest-first), per watched range, and per recorded
    /// syscall, in that order. Does not mutate any instrument.
    pub fn trace_snapshot(&self) -> Vec<String> {
        let mut out = Vec::new();
        for (i, ev) in self.trace.iter().enumerate() {
            out.push(format!(
                "trace[{i}]: pc={pc:08x} word={word:08x} {dis}",
                pc = ev.pc,
                word = ev.word,
                dis = ev.disasm
            ));
        }
        for r in &self.mem_watch.ranges {
            out.push(format!(
                "watch: addr={addr:08x} len={len:08x}",
                addr = r.addr,
                len = r.len
            ));
        }
        for e in self.syscall_log.recent(usize::MAX) {
            out.push(format!(
                "syscall: id={id} pc={pc:08x}",
                id = e.id,
                pc = e.pc
            ));
        }
        out
    }
}

impl Default for Debugger {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn breakpoints_and_disasm() {
        let mut dbg = Debugger::new();
        dbg.add_breakpoint(0x1001);
        assert!(dbg.is_breakpoint(0x1000));
        let mem = Memory::new();
        let lines = dbg.disasm_at(&mem, 0x1000, 2);
        assert_eq!(lines.len(), 2);
    }

    #[test]
    fn trace_respects_capacity() {
        let mut buf = TraceBuffer::new(4);
        for i in 0..10u32 {
            buf.push(0x1000 + i * 4, 0x6000_0000);
        }
        assert_eq!(buf.len(), 4);
        assert_eq!(buf.capacity(), 4);
    }

    #[test]
    fn trace_overwrites_oldest_in_order() {
        let mut buf = TraceBuffer::new(3);
        for i in 0..5u32 {
            buf.push(0x1000 + i * 4, 0x6000_0000);
        }
        let pcs: Vec<u32> = buf.iter().map(|e| e.pc).collect();
        assert_eq!(pcs, vec![0x1008, 0x100C, 0x1010]);
    }

    #[test]
    fn trace_push_records_real_disasm() {
        let mut buf = TraceBuffer::new(8);
        buf.push(0x2000, 0x6000_0000);
        let ev = buf.iter().next().expect("one event");
        assert_eq!(ev.pc, 0x2000);
        assert_eq!(ev.word, 0x6000_0000);
        assert!(ev.disasm.contains("Nop"), "got: {}", ev.disasm);
        // Unknown encoding is still decoded explicitly, never blank.
        buf.push(0x2004, 0xFFFF_FFFF);
        let words: Vec<u32> = buf.iter().map(|e| e.word).collect();
        assert_eq!(words, vec![0x6000_0000, 0xFFFF_FFFF]);
    }

    #[test]
    fn trace_clear_empties() {
        let mut buf = TraceBuffer::new(4);
        buf.push(0x1000, 0x6000_0000);
        buf.push(0x1004, 0x6000_0000);
        assert!(!buf.is_empty());
        buf.clear();
        assert!(buf.is_empty());
        assert_eq!(buf.len(), 0);
        assert_eq!(buf.iter().count(), 0);
    }

    #[test]
    fn trace_zero_capacity_push_is_noop() {
        let mut buf = TraceBuffer::new(0);
        buf.push(0x1000, 0x6000_0000);
        assert!(buf.is_empty());
    }

    #[test]
    fn memwatch_hit_and_miss() {
        let mut w = MemWatch::new();
        assert!(!w.check(0x1000, 4));
        w.watch(0x1000, 0x100);
        assert!(w.check(0x1000, 4));
        assert!(w.check(0x10F0, 0x20));
        assert!(w.check(0x0FF0, 0x20));
        assert!(!w.check(0x2000, 4));
        assert_eq!(w.len(), 1);
    }

    #[test]
    fn memwatch_adjacent_does_not_overlap() {
        let mut w = MemWatch::new();
        w.watch(0x1000, 0x100);
        // Probe starting exactly at the range end.
        assert!(!w.check(0x1100, 0x10));
        // Probe ending exactly at the range start.
        assert!(!w.check(0x0FF0, 0x10));
        // Single byte just past the end.
        assert!(!w.check(0x1100, 1));
        // Single byte at the last covered address still hits.
        assert!(w.check(0x10FF, 1));
    }

    #[test]
    fn memwatch_any_range_matches_and_unwatch() {
        let mut w = MemWatch::new();
        w.watch(0x1000, 0x10);
        w.watch(0x2000, 0x10);
        assert!(w.check(0x2004, 4));
        w.unwatch(0x2000);
        assert!(!w.check(0x2004, 4));
        assert!(w.check(0x1004, 4));
        w.unwatch(0x1000);
        assert!(w.is_empty());
    }

    #[test]
    fn memwatch_zero_lengths_never_match() {
        let mut w = MemWatch::new();
        w.watch(0x1000, 0);
        assert!(!w.check(0x1000, 4));
        assert!(!w.check(0x1000, 0));
        w.clear();
        w.watch(0x1000, 0x100);
        assert!(!w.check(0x1000, 0));
        assert!(!w.check(0x5000, 0));
    }

    #[test]
    fn syscall_record_and_count() {
        let mut log = SyscallLog::new(8);
        assert_eq!(log.count(), 0);
        assert!(log.is_empty());
        log.record(1, 0x1000);
        log.record(2, 0x1004);
        assert_eq!(log.count(), 2);
        assert!(!log.is_empty());
    }

    #[test]
    fn syscall_recent_returns_last_n_oldest_first() {
        let mut log = SyscallLog::new(8);
        for i in 0..5u32 {
            log.record(i, 0x1000 + i * 4);
        }
        let last_two = log.recent(2);
        assert_eq!(
            last_two,
            vec![
                SyscallEntry { id: 3, pc: 0x100C },
                SyscallEntry { id: 4, pc: 0x1010 },
            ]
        );
        // Asking for more than held returns everything, oldest-first.
        let all = log.recent(99);
        assert_eq!(all.len(), 5);
        assert_eq!(all[0].id, 0);
        // Zero returns nothing.
        assert!(log.recent(0).is_empty());
    }

    #[test]
    fn syscall_bounded_log_drops_oldest() {
        let mut log = SyscallLog::new(3);
        for i in 0..5u32 {
            log.record(i, 0x1000 + i * 4);
        }
        assert_eq!(log.count(), 3);
        assert_eq!(log.capacity(), 3);
        let ids: Vec<u32> = log.recent(usize::MAX).iter().map(|e| e.id).collect();
        assert_eq!(ids, vec![2, 3, 4]);
        log.clear();
        assert_eq!(log.count(), 0);
    }

    #[test]
    fn debugger_snapshot_reflects_instruments() {
        let mut dbg = Debugger::new();
        assert!(dbg.trace_snapshot().is_empty());
        dbg.trace.push(0x1000, 0x6000_0000);
        dbg.mem_watch.watch(0x2000, 0x40);
        dbg.syscall_log.record(7, 0x1000);
        let snap = dbg.trace_snapshot();
        assert_eq!(snap.len(), 3);
        assert!(snap[0].starts_with("trace[0]:"), "got: {}", snap[0]);
        assert!(snap[0].contains("00001000"), "got: {}", snap[0]);
        assert!(snap[0].contains("Nop"), "got: {}", snap[0]);
        assert!(snap[1].contains("00002000"), "got: {}", snap[1]);
        assert!(snap[2].contains('7'), "got: {}", snap[2]);
        assert!(snap[2].contains("00001000"), "got: {}", snap[2]);
        // Snapshot is inspect-only: state is unchanged afterwards.
        assert_eq!(dbg.trace.len(), 1);
        assert_eq!(dbg.syscall_log.count(), 1);
        assert_eq!(dbg.trace_snapshot().len(), 3);
    }

    #[test]
    fn debugger_defaults_hold_empty_instruments() {
        let dbg = Debugger::default();
        assert!(dbg.trace.is_empty());
        assert!(dbg.mem_watch.is_empty());
        assert!(dbg.syscall_log.is_empty());
        assert_eq!(dbg.trace.capacity(), DEFAULT_TRACE_CAPACITY);
        assert_eq!(dbg.syscall_log.capacity(), DEFAULT_SYSCALL_CAPACITY);
    }
}
