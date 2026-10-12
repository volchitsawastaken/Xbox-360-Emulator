//! Threads, sync primitives, syscalls, XAM services.

use std::collections::{HashMap, VecDeque};
use x360_common::{EmuError, Result};
use x360_cpu::regs::ThreadState;

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
}

impl Kernel {
    pub fn new() -> Self {
        Self {
            next_handle: 1,
            threads: HashMap::new(),
            ready: VecDeque::new(),
            events: HashMap::new(),
            syscall_count: 0,
            unimplemented_syscalls: HashMap::new(),
        }
    }

    fn alloc(&mut self) -> Handle {
        let h = Handle(self.next_handle);
        self.next_handle += 1;
        h
    }

    pub fn create_thread(&mut self, entry: u32, priority: u8) -> Handle {
        let h = self.alloc();
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
        let h = self.alloc();
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
    pub fn syscall(&mut self, id: u32, _args: &[u32]) -> Result<u32> {
        self.syscall_count += 1;
        match id {
            // 0: GetTickCount-style stub with real time base.
            0 => Ok(std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u32)
                .unwrap_or(0)),
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
