//! Kernel export dispatch for import-thunk traps.
//!
//! Called by the boot runner when `sc` fires inside a rewritten thunk
//! (`thunk_addr = pc_after_sc - 4`). Arguments follow the PPC ABI in
//! `r3..r10`; results return in `r3` (and `r4` for 64-bit splits).
//!
//! Numeric facts (NTSTATUS codes, `X_MEM`/`X_PAGE` flags, struct
//! layouts) are ported from the BSD-licensed Xenia `xbox.h`,
//! `kernel.h`, and `xboxkrnl_rtl.cc` / `xboxkrnl_memory.cc` /
//! `xboxkrnl_threading.cc` / `xboxkrnl_modules.cc` (facts only, all
//! code original). Unimplemented imports are explicit `Unsupported`
//! errors with per-import call counts, never fake success.

use x360_common::{EmuError, Result};
use x360_cpu::regs::ThreadState;
use x360_memory::Memory;

use super::imports::{ImportTable, ResolvedImport};
use super::Kernel;

// NTSTATUS codes (reference `xbox.h`).
pub const STATUS_SUCCESS: u32 = 0x0000_0000;
pub const STATUS_TIMEOUT: u32 = 0x0000_0102;
pub const STATUS_NO_MEMORY: u32 = 0xC000_0017;
pub const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
pub const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
pub const STATUS_OBJECT_TYPE_MISMATCH: u32 = 0xC000_0024;
pub const STATUS_MUTANT_NOT_OWNED: u32 = 0xC000_0046;
pub const STATUS_SEMAPHORE_LIMIT_EXCEEDED: u32 = 0xC000_0047;
pub const STATUS_BUFFER_TOO_SMALL: u32 = 0x8000_0005;
pub const STATUS_INVALID_PARAMETER_3: u32 = 0xC000_00F1;
pub const STATUS_INVALID_INFO_CLASS: u32 = 0xC000_0003;
pub const STATUS_INFO_LENGTH_MISMATCH: u32 = 0xC000_0004;
pub const STATUS_PENDING: u32 = 0x0000_0103;
// Win32-flavored errors for module APIs (reference `xbox.h`).
pub const ERROR_SUCCESS: u32 = 0x0000_0000;
pub const ERROR_NOT_FOUND: u32 = 0x0000_0490;

// Allocation types (reference `kernel.h` X_MEM).
const MEM_COMMIT: u32 = 0x0000_1000;
const MEM_RESERVE: u32 = 0x0000_2000;
const MEM_RESET: u32 = 0x0008_0000;
// Note: MEM_TOP_DOWN (0x00100000) is accepted but allocation always grows
// upward from the heap base; direction is logged, never an error.
const MEM_NOZERO: u32 = 0x0080_0000;
const MEM_LARGE_PAGES: u32 = 0x2000_0000;

// Critical-section guest layout (reference `xboxkrnl_rtl.cc`
// `X_RTL_CRITICAL_SECTION`, 28 bytes: 16-byte dispatch header plus
// lock_count, recursion_count, owning_thread; header type 1 =
// EventSynchronizationObject from `xobject.h`).
const CS_LOCK: u32 = 0x10;
const CS_RECURSION: u32 = 0x14;
const CS_OWNER: u32 = 0x18;

fn arg(t: &ThreadState, i: usize) -> u32 {
    t.gpr[3 + i] as u32
}

fn read_u16be(mem: &Memory, addr: u32) -> Result<u16> {
    let b = mem.read_bytes(addr, 2)?;
    Ok(u16::from_be_bytes([b[0], b[1]]))
}

fn write_u16be(mem: &mut Memory, addr: u32, v: u16) -> Result<()> {
    mem.write_bytes(addr, &v.to_be_bytes())
}

fn read_i32be(mem: &Memory, addr: u32) -> Result<i32> {
    Ok(mem.read_u32(addr)? as i32)
}

fn write_i32be(mem: &mut Memory, addr: u32, v: i32) -> Result<()> {
    mem.write_u32(addr, v as u32)
}

/// Read a guest C string (up to 4 KiB, NUL-terminated).
fn read_cstr(mem: &Memory, ptr: u32) -> Result<Vec<u8>> {
    if ptr == 0 {
        return Err(EmuError::Other("null string pointer".into()));
    }
    let mut out = Vec::new();
    for i in 0..4096u32 {
        let b = mem.read_u8(ptr.wrapping_add(i))?;
        if b == 0 {
            return Ok(out);
        }
        out.push(b);
    }
    Err(EmuError::Other("unterminated guest string".into()))
}

/// Dispatch one import call. On return the boot runner continues at
/// the post-`sc` word (`blr`), so handlers only set registers/memory.
pub fn dispatch_import(
    kernel: &mut Kernel,
    mem: &mut Memory,
    table: &mut ImportTable,
    thread_id: u32,
    t: &mut ThreadState,
    imp: &ResolvedImport,
) -> Result<()> {
    let lib = imp.lib.to_ascii_lowercase();
    let ord = imp.ordinal;
    let key = (imp.lib.clone(), ord);
    match (lib_kind(&lib), ord) {
        (Lib::Xboxkrnl, 0x12E) => rtl_init_cs(kernel, mem, arg(t, 0), 0, t),
        (Lib::Xboxkrnl, 0x12F) => rtl_init_cs(kernel, mem, arg(t, 0), arg(t, 1), t),
        (Lib::Xboxkrnl, 0x125) => rtl_enter_cs(kernel, mem, thread_id, arg(t, 0), t),
        (Lib::Xboxkrnl, 0x130) => rtl_leave_cs(kernel, mem, thread_id, arg(t, 0), t),
        (Lib::Xboxkrnl, 0x141) => rtl_try_enter_cs(kernel, mem, thread_id, arg(t, 0), t),
        (Lib::Xboxkrnl, 0x12C) => rtl_init_ansi(mem, arg(t, 0), arg(t, 1), t),
        (Lib::Xboxkrnl, 0x12D) => rtl_init_unicode(mem, arg(t, 0), arg(t, 1), t),
        (Lib::Xboxkrnl, 0x127) => rtl_free_string(mem, arg(t, 0), t),
        (Lib::Xboxkrnl, 0x128) => rtl_free_string(mem, arg(t, 0), t),
        (Lib::Xboxkrnl, 0x121) => rtl_copy_string(mem, arg(t, 0), arg(t, 1), 1, t),
        (Lib::Xboxkrnl, 0x122) => rtl_copy_string(mem, arg(t, 0), arg(t, 1), 2, t),
        (Lib::Xboxkrnl, 0x11A) => rtl_compare_memory(mem, arg(t, 0), arg(t, 1), arg(t, 2), t),
        (Lib::Xboxkrnl, 0x11B) => rtl_compare_memory_ulong(mem, arg(t, 0), arg(t, 1), arg(t, 2), t),
        (Lib::Xboxkrnl, 0x126) => rtl_fill_ulong(mem, arg(t, 0), arg(t, 1), arg(t, 2), t),
        (Lib::Xboxkrnl, 0x09) => ex_alloc_pool(kernel, mem, arg(t, 0), t),
        (Lib::Xboxkrnl, 0x0A) => ex_alloc_pool(kernel, mem, arg(t, 0), t),
        (Lib::Xboxkrnl, 0x0B) => ex_alloc_pool(kernel, mem, arg(t, 0), t),
        (Lib::Xboxkrnl, 0x0F) => ex_free_pool(kernel, arg(t, 0), t),
        (Lib::Xboxkrnl, 0x13) => ex_query_pool_size(kernel, arg(t, 0), t),
        (Lib::Xboxkrnl, 0xCC) => {
            nt_alloc_virt(kernel, mem, arg(t, 0), arg(t, 1), arg(t, 2), arg(t, 3), t)
        }
        (Lib::Xboxkrnl, 0xDC) => nt_free_virt(kernel, mem, arg(t, 0), arg(t, 1), arg(t, 2), t),
        (Lib::Xboxkrnl, 0xEE) => nt_query_virt(kernel, mem, arg(t, 0), arg(t, 1), t),
        (Lib::Xboxkrnl, 0xB9) => mm_alloc_phys(kernel, mem, arg(t, 1), arg(t, 2), t),
        (Lib::Xboxkrnl, 0xBA) => mm_alloc_phys_ex(kernel, mem, t),
        (Lib::Xboxkrnl, 0xBD) => mm_free_phys(kernel, arg(t, 1), t),
        (Lib::Xboxkrnl, 0xC5) => mm_query_alloc_size(kernel, arg(t, 0), t),
        (Lib::Xboxkrnl, 0xBE) => {
            // MmGetPhysicalAddress(virt): mirror collapse (reference
            // `GetPhysicalAddress`; 0 when unmapped, never fabricated).
            t.gpr[3] = (mem.to_physical(arg(t, 0))) as u64;
            Ok(())
        }
        // ---- File system (reference `xboxkrnl_io.cc`) ----
        (Lib::Xboxkrnl, 0xD2) => nt_create_file(
            kernel,
            mem,
            arg(t, 0),
            arg(t, 1),
            arg(t, 2),
            arg(t, 3),
            arg(t, 5),
            arg(t, 6),
            arg(t, 7),
            crate::fs::stack_arg(mem, t.gpr[1] as u32, 0).unwrap_or(0),
            t,
        ),
        (Lib::Xboxkrnl, 0xDF) => nt_create_file(
            kernel,
            mem,
            arg(t, 0),
            arg(t, 1),
            arg(t, 2),
            arg(t, 3),
            0,
            0,
            crate::fs::DISP_OPEN,
            arg(t, 4),
            t,
        ),
        (Lib::Xboxkrnl, 0xF0) => nt_read_file(
            kernel,
            mem,
            arg(t, 0),
            arg(t, 1),
            arg(t, 2),
            arg(t, 3),
            arg(t, 4),
            arg(t, 5),
            arg(t, 6),
            arg(t, 7),
            t,
        ),
        (Lib::Xboxkrnl, 0xCF) => nt_close_file(kernel, arg(t, 0), t),
        (Lib::Xboxkrnl, 0xE8) => nt_query_info_file(
            kernel,
            mem,
            arg(t, 0),
            arg(t, 1),
            arg(t, 2),
            arg(t, 3),
            arg(t, 4),
            t,
        ),
        // FscGet/SetCacheElementCount (reference `xboxkrnl_io.cc`):
        // both stubs returning 0/SUCCESS; no cache backend exists.
        (Lib::Xboxkrnl, 0x20) => {
            t.gpr[3] = 0_u64;
            Ok(())
        }
        (Lib::Xboxkrnl, 0x21) => {
            t.gpr[3] = 0_u64;
            Ok(())
        }
        // HalGetCurrentAVPack (reference `xboxkrnl_hal.cc`): 8 = HDMI,
        // the reference default, matching Xam 0x3CB.
        (Lib::Xboxkrnl, 0x22) => {
            t.gpr[3] = 8_u64;
            Ok(())
        }
        // KeInitializeDpc(dpc, routine, context) (reference
        // `xthread.h` `XDPC::Initialize`): type=19, both CPUs 0,
        // routine + context stored; list_entry/args untouched.
        (Lib::Xboxkrnl, 0x6F) => {
            let (dpc, routine, context) = (arg(t, 0), arg(t, 1), arg(t, 2));
            write_u16be(mem, dpc, 19)?;
            mem.write_u8(dpc + 2, 0)?;
            mem.write_u8(dpc + 3, 0)?;
            mem.write_u32(dpc + 12, routine)?;
            mem.write_u32(dpc + 16, context)?;
            Ok(())
        }
        // ObCreateSymbolicLink(path, target) (reference
        // `xboxkrnl_ob.cc`): register the mapping, stripping the
        // `\??\` / `\System??\` qualifier. Re-registering the same
        // mapping is success (the reference checks first, and one
        // title expects success for it).
        (Lib::Xboxkrnl, 0x103) => ob_create_symlink(kernel, mem, arg(t, 0), arg(t, 1), t),
        (Lib::Xboxkrnl, 0x152) => ke_tls_alloc(kernel, t),
        (Lib::Xboxkrnl, 0x153) => ke_tls_free(kernel, arg(t, 0), t),
        (Lib::Xboxkrnl, 0x154) => ke_tls_get(kernel, arg(t, 0), t),
        (Lib::Xboxkrnl, 0x155) => ke_tls_set(kernel, arg(t, 0), arg(t, 1), t),
        (Lib::Xboxkrnl, 0x84) => ke_query_system_time(mem, arg(t, 0), t),
        (Lib::Xboxkrnl, 0x83) => ke_query_perf_freq(mem, arg(t, 0), t),
        (Lib::Xboxkrnl, 0x66) => {
            t.gpr[3] = 1_u64; // title process
            Ok(())
        }
        // ---- NT sync objects (reference `xboxkrnl_threading.cc`) ----
        (Lib::Xboxkrnl, 0xD1) => nt_create_event(kernel, mem, arg(t, 0), arg(t, 2), arg(t, 3), t),
        (Lib::Xboxkrnl, 0xD5) => {
            nt_create_semaphore(kernel, mem, arg(t, 0), arg(t, 2), arg(t, 3), t)
        }
        (Lib::Xboxkrnl, 0xD4) => nt_create_mutant(kernel, mem, arg(t, 0), arg(t, 2), thread_id, t),
        (Lib::Xboxkrnl, 0xD7) => nt_create_timer(kernel, mem, arg(t, 0), arg(t, 2), t),
        (Lib::Xboxkrnl, 0xF3) => {
            nt_release_semaphore(kernel, mem, arg(t, 0), arg(t, 1), arg(t, 2), t)
        }
        (Lib::Xboxkrnl, 0xF2) => nt_release_mutant(kernel, mem, thread_id, arg(t, 0), t),
        (Lib::Xboxkrnl, 0xF6) => nt_set_event(kernel, mem, arg(t, 0), arg(t, 1), t),
        (Lib::Xboxkrnl, 0xCE) => nt_clear_event(kernel, mem, arg(t, 0), t),
        (Lib::Xboxkrnl, 0xE2) => nt_pulse_event(kernel, mem, arg(t, 0), arg(t, 1), t),
        (Lib::Xboxkrnl, 0xFD) => nt_wait_single(kernel, mem, arg(t, 0), thread_id, t),
        (Lib::Xboxkrnl, 0xFE) => {
            nt_wait_multiple(kernel, mem, arg(t, 0), arg(t, 1), arg(t, 2), thread_id, t)
        }
        // ---- NT threads (reference `xboxkrnl_threading.cc`) ----
        (Lib::Xboxkrnl, 0x0D) => ex_create_thread(
            kernel,
            mem,
            arg(t, 0),
            arg(t, 1),
            arg(t, 2),
            arg(t, 3),
            arg(t, 4),
            arg(t, 5),
            arg(t, 6),
            t,
        ),
        (Lib::Xboxkrnl, 0xF5) => nt_resume_thread(kernel, mem, arg(t, 0), arg(t, 1), t),
        (Lib::Xboxkrnl, 0xFC) => nt_suspend_thread(kernel, mem, arg(t, 0), arg(t, 1), t),
        (Lib::Xboxkrnl, 0x19) => ex_terminate_thread(kernel, thread_id, arg(t, 0), t),
        (Lib::Xboxkrnl, 0x101) => {
            // NtYieldExecution: cooperative yield is a no-op with one
            // running thread; still a real return, not a stub.
            t.gpr[3] = (STATUS_SUCCESS) as u64;
            Ok(())
        }
        // ---- Object manager (reference `xboxkrnl_ob.cc`) ----
        (Lib::Xboxkrnl, 0x110) => {
            ob_reference_by_handle(kernel, mem, arg(t, 0), arg(t, 1), arg(t, 2), t)
        }
        (Lib::Xboxkrnl, 0x105) => {
            // ObDereferenceObject(ptr): void in the reference; release
            // nothing (handles stay valid), leave r3 alone.
            let _ = arg(t, 0);
            Ok(())
        }
        (Lib::Xboxkrnl, 0x10B) | (Lib::Xboxkrnl, 0x10A) => {
            ob_lookup_thread(kernel, mem, arg(t, 0), arg(t, 1), t)
        }
        // KeEnter/LeaveCriticalRegion: void; nest count only.
        (Lib::Xboxkrnl, 0x5F) => {
            kernel.critical_region += 1;
            Ok(())
        }
        (Lib::Xboxkrnl, 0x7D) => {
            if kernel.critical_region == 0 {
                log::warn!("kernel: KeLeaveCriticalRegion without enter");
            } else {
                kernel.critical_region -= 1;
            }
            Ok(())
        }
        // ---- Ke* thread APIs (reference `xboxkrnl_threading.cc`) ----
        (Lib::Xboxkrnl, 0x97) => ke_set_affinity(kernel, mem, arg(t, 0), arg(t, 1), arg(t, 2), t),
        (Lib::Xboxkrnl, 0x81) => ke_query_priority(kernel, arg(t, 0), t),
        (Lib::Xboxkrnl, 0x99) => ke_set_priority(kernel, mem, arg(t, 0), arg(t, 1), t),
        (Lib::Xboxkrnl, 0x9C) => ke_set_boost(kernel, mem, arg(t, 0), arg(t, 1), t),
        (Lib::Xboxkrnl, 0x92) => ke_resume_ptr(kernel, mem, arg(t, 0), t),
        (Lib::Xboxkrnl, 0xA9) => ke_suspend_ptr(kernel, mem, arg(t, 0), t),
        (Lib::Xboxkrnl, 0x5A) => ke_delay_thread(mem, arg(t, 0), arg(t, 1), arg(t, 2), t),
        // ---- XConfig (reference `xboxkrnl_xconfig.cc`) ----
        (Lib::Xboxkrnl, 0x10) => ex_get_xconfig(
            mem,
            (arg(t, 0) & 0xFFFF) as u16,
            (arg(t, 1) & 0xFFFF) as u16,
            arg(t, 2),
            (arg(t, 3) & 0xFFFF) as u16,
            arg(t, 4),
            t,
        ),
        // ---- Video driver (reference `xboxkrnl_video.cc`) ----
        (Lib::Xboxkrnl, 0x1C2) => {
            // VdInitializeEngines(unk, callback, arg, pfp, me):
            // records the microcode + callback for the GPU backend,
            // returns 1 like the reference.
            kernel.vd_engines = Some(crate::VdEngines {
                unk0: arg(t, 0),
                callback: arg(t, 1),
                arg: arg(t, 2),
                pfp_ptr: arg(t, 3),
                me_ptr: arg(t, 4),
            });
            t.gpr[3] = 1_u64;
            Ok(())
        }
        // ExRegisterTitleTerminateNotification(reg, create): void in
        // the reference; tracks {routine, priority} (reference
        // `xboxkrnl_modules.cc`).
        (Lib::Xboxkrnl, 0x15) => {
            let reg = arg(t, 0);
            let create = arg(t, 1);
            if reg != 0 {
                let routine = mem.read_u32(reg).unwrap_or(0);
                let priority = mem.read_u32(reg + 4).unwrap_or(0);
                if create != 0 {
                    kernel
                        .terminate_notifications
                        .retain(|n| n.routine != routine);
                    kernel
                        .terminate_notifications
                        .push(crate::TerminateNotification { routine, priority });
                } else {
                    kernel
                        .terminate_notifications
                        .retain(|n| n.routine != routine);
                }
            }
            Ok(())
        }
        // Read-write locks (reference `xboxkrnl_threading.cc`
        // `X_ERWLOCK`, 0x38 bytes). Single-threaded guest-memory
        // implementation: uncontended acquire/release behave exactly;
        // a contended blocking acquire is an explicit Unsupported
        // (no fake success, no silent spin) since this runner cannot
        // block one thread while another holds the lock.
        (Lib::Xboxkrnl, 0x11) => erw_init(mem, arg(t, 0)),
        (Lib::Xboxkrnl, 0x07) => erw_acquire(mem, arg(t, 0), true),
        (Lib::Xboxkrnl, 0x08) => erw_acquire(mem, arg(t, 0), false),
        (Lib::Xboxkrnl, 0x2DD) => erw_try(mem, arg(t, 0), true, t),
        (Lib::Xboxkrnl, 0x2DE) => erw_try(mem, arg(t, 0), false, t),
        (Lib::Xboxkrnl, 0x16) => erw_release(mem, arg(t, 0)),
        // EtxProducerRegister(...): event-tracing registration. The
        // reference has no implementation (table-only `kFunction`).
        // Tracing is observational: report success without storing
        // anything (no ETX consumer exists to read it back).
        (Lib::Xboxkrnl, 0x334) => {
            t.gpr[3] = 0_u64;
            Ok(())
        }
        // XUsbcamGetState (reference `xboxkrnl_usbcam.cc`): no camera
        // is attached, so CamNotConnected (0).
        (Lib::Xboxkrnl, 0x21D) => {
            t.gpr[3] = 0_u64;
            Ok(())
        }
        // XeCryptRandom(buf, len) (reference `xboxkrnl_crypt.cc`):
        // void; fills with 0xFD (the reference's deterministic stub,
        // kept for run-to-run reproducibility).
        (Lib::Xboxkrnl, 0x18A) => {
            let (buf, len) = (arg(t, 0), arg(t, 1));
            if len != 0 {
                mem.write_bytes(buf, &vec![0xFD; len as usize])?;
            }
            Ok(())
        }
        // ---- Video ring/command buffer (reference
        // `xboxkrnl_video.cc`) ----
        (Lib::Xboxkrnl, 0x1D5) => {
            // VdSetGraphicsInterruptCallback(callback, user_data): void.
            kernel.vd_interrupt = Some((arg(t, 0), arg(t, 1)));
            Ok(())
        }
        (Lib::Xboxkrnl, 0x1C3) => {
            // VdInitializeRingBuffer(ptr, size_log2): void. `ptr` is
            // the MmGetPhysicalAddress of a WRITE_COMBINE Mm block.
            // Reference (`command_processor.cc`
            // `CommandProcessor::InitializeRingBuffer`) zeroes
            // `1 << (size_log2 + 3)` bytes at the buffer and records
            // it as the primary ring; the read pointer starts at 0.
            // Physical DRAM maps 1:1 here (`to_physical` is the
            // identity below 512MB), so zero the range in place.
            let (ptr, log2) = (arg(t, 0), arg(t, 1));
            let size = 1u64
                .checked_shl(log2.saturating_add(3))
                .ok_or_else(|| EmuError::Other(format!("ring size_log2 {} overflows", log2)))?;
            let end = (ptr as u64)
                .checked_add(size)
                .ok_or_else(|| EmuError::Other("ring range overflows".into()))?;
            if end > x360_memory::MEM_SIZE as u64 {
                return Err(EmuError::Other(format!(
                    "ring buffer {:08x}+{} outside DRAM",
                    ptr, size
                )));
            }
            if size != 0 {
                mem.write_bytes(ptr, &vec![0u8; size as usize])?;
            }
            kernel.vd_ring = Some((ptr, log2));
            Ok(())
        }
        (Lib::Xboxkrnl, 0x1B6) => {
            // VdEnableRingBufferRPtrWriteBack(ptr, block_log2): void.
            kernel.vd_rptr_wb = Some((arg(t, 0), arg(t, 1)));
            Ok(())
        }
        (Lib::Xboxkrnl, 0x1BD) => {
            // VdGetSystemCommandBuffer(p0, p1): p0 zeroed 0x94 with
            // 0xBEEF0000 first, p1 = 0xBEEF0001.
            let p0 = arg(t, 0);
            let p1 = arg(t, 1);
            if p0 != 0 {
                mem.write_bytes(p0, &[0u8; 0x94])?;
                mem.write_u32(p0, 0xBEEF_0000)?;
            }
            if p1 != 0 {
                mem.write_u32(p1, 0xBEEF_0001)?;
            }
            Ok(())
        }
        (Lib::Xboxkrnl, 0x1BC) => {
            // VdGetGraphicsAsicID: 0x11 (games with < 0x10 take the
            // EDRAM-retrain path instead).
            t.gpr[3] = 0x11_u64;
            Ok(())
        }
        (Lib::Xboxkrnl, 0x1C6) => {
            // VdIsHSIOTrainingSucceeded: TRUE.
            t.gpr[3] = 1_u64;
            Ok(())
        }
        // VdRetrainEDRAM(Worker): 0 in the reference.
        (Lib::Xboxkrnl, 0x269) | (Lib::Xboxkrnl, 0x26A) => {
            t.gpr[3] = 0_u64;
            Ok(())
        }
        (Lib::Xboxkrnl, 0x1C7) => {
            // VdPersistDisplay(unk, out_ptr): 64-byte block + 1
            // (reference allocates 64/align-32 from its heap).
            let out = arg(t, 1);
            let addr = kernel.alloc_mem(64, 32)?;
            mem.write_bytes(addr, &[0u8; 64])?;
            if out != 0 {
                mem.write_u32(out, addr)?;
            }
            t.gpr[3] = 1_u64;
            Ok(())
        }
        (Lib::Xboxkrnl, 0x1DC) => {
            // VdShutdownEngines: void, ignored in the reference.
            Ok(())
        }
        (Lib::Xboxkrnl, 0x1D3) => {
            // VdSetDisplayMode(flags): 0 in the reference.
            t.gpr[3] = 0_u64;
            Ok(())
        }
        (Lib::Xboxkrnl, 0x1B1) => {
            // VdCallGraphicsNotificationRoutines(unk, args_ptr): the
            // reference asserts unk==1 and returns 0 without invoking
            // anything (no routines can be registered: the register
            // call has no implementation even in the reference).
            if arg(t, 0) != 1 {
                log::warn!(
                    "kernel: VdCallGraphicsNotificationRoutines unk={:08x}",
                    arg(t, 0)
                );
            }
            t.gpr[3] = 0_u64;
            Ok(())
        }
        (Lib::Xboxkrnl, 0x1B9) => {
            // VdGetCurrentDisplayGamma(type_ptr, power_ptr): TV
            // (BT.709) + 2.22222233, the reference cvar defaults.
            let ty = arg(t, 0);
            let pw = arg(t, 1);
            if ty != 0 {
                mem.write_u32(ty, 2)?;
            }
            if pw != 0 {
                // Reference default `kernel_display_gamma_power`
                // (f64 cvar 2.22222233, read back as float).
                mem.write_bytes(pw, &(2.22222233_f64 as f32).to_be_bytes())?;
            }
            Ok(())
        }
        // VdQueryVideoMode/VdQueryRealVideoMode(mode_ptr): 1280x720
        // HDMI default (reference `VdQueryVideoMode` with the default
        // `av_pack_hdmi_sz` + NTSCM region: widescreen, hi-def, 60Hz,
        // pixel_rate 0x8A). Layout from `kernel.h` `X_VIDEO_MODE`.
        (Lib::Xboxkrnl, 0x1CA) | (Lib::Xboxkrnl, 0x2D2) => vd_query_video_mode(mem, arg(t, 0), t),
        (Lib::Xboxkrnl, 0x1C9) => {
            // VdQueryVideoFlags: widescreen|>=1280 for the mode above.
            t.gpr[3] = 3_u64;
            Ok(())
        }
        (Lib::Xboxkrnl, 0x1D9) => {
            // VdSetSystemCommandBufferGpuIdentifierAddress(addr): void
            // stub in the reference; record for the GPU backend.
            kernel.vd_gpu_identifier = Some(arg(t, 0));
            Ok(())
        }
        (Lib::Xboxkrnl, 0x379) => {
            // VdSetStudioRGBMode(mode): table-only in the reference.
            // Record the limited/full-range selection for the GPU
            // backend; return 0 like the other Vd setters.
            kernel.vd_studio_rgb = Some(arg(t, 0));
            t.gpr[3] = 0_u64;
            Ok(())
        }
        // KiApcNormalRoutineNop(_): returns 0 (reference stub); also
        // exported as KiApcNormalRoutineNop_ (0x19D).
        (Lib::Xboxkrnl, 0x1DF) | (Lib::Xboxkrnl, 0x19D) => {
            t.gpr[3] = 0_u64;
            Ok(())
        }
        (Lib::Xboxkrnl, 0x12B) => rtl_xex_header_field(kernel, arg(t, 0), arg(t, 1), t),
        (Lib::Xboxkrnl, 0x12A) => rtl_get_stack_limits(kernel, mem, arg(t, 0), arg(t, 1), t),
        (Lib::Xboxkrnl, 0x135) => rtl_nt_status_to_dos_error(arg(t, 0), t),
        (Lib::Xboxkrnl, 0x195) => xex_get_module_handle(kernel, mem, arg(t, 0), arg(t, 1), t),
        (Lib::Xboxkrnl, 0x194) => xex_check_privilege(kernel, arg(t, 0), t),
        (Lib::Xboxkrnl, 0x03) => {
            let fmt = read_cstr(mem, arg(t, 0)).unwrap_or_default();
            log::info!("guest DbgPrint: {}", String::from_utf8_lossy(&fmt));
            t.gpr[3] = 0_u64;
            Ok(())
        }
        // ---- XAM ----
        // AV pack for PAL checks (reference `am_info.cc`; 8 = HDMI,
        // the reference default; 3/4/6/8 are the non-exploding set).
        (Lib::Xam, 0x3CB) => {
            t.gpr[3] = 8_u64;
            Ok(())
        }
        // System version (reference returns 0: older is safer).
        (Lib::Xam, 0x282) => {
            t.gpr[3] = 0_u64;
            Ok(())
        }
        // Current title id: the genuinely loaded title.
        (Lib::Xam, 0x1CF) => {
            t.gpr[3] = (kernel.title_id) as u64;
            Ok(())
        }
        // NetDll_WSAStartup (reference `xam_net.cc` `X_WSADATA`,
        // 0x190 bytes; non-Windows path echoes the requested version
        // with high 0x0202 and returns 0). Stateless success for now;
        // real sockets arrive with socket()/connect() shims.
        (Lib::Xam, 0x1) => netdll_wsa_startup(mem, arg(t, 1), arg(t, 2), t),
        // XAM notifications (reference `am_notify.cc`).
        (Lib::Xam, 0x28A) => {
            // Mask arrives as a full 64-bit register, not two halves.
            let h = kernel.notify_create(t.gpr[3], false, arg(t, 1));
            t.gpr[3] = (h) as u64;
            Ok(())
        }
        (Lib::Xam, 0x291) => {
            let h = kernel.notify_create(t.gpr[3], arg(t, 1) != 0, arg(t, 2));
            t.gpr[3] = (h) as u64;
            Ok(())
        }
        (Lib::Xam, 0x28B) => {
            xnotify_get_next(kernel, mem, arg(t, 0), arg(t, 1), arg(t, 2), arg(t, 3), t)
        }
        (Lib::Xam, 0x28C) => {
            // XNotifyPositionUI: void in the reference; record the word.
            kernel.notify_position = arg(t, 0);
            Ok(())
        }
        (Lib::Xam, 0x28D) => {
            // XNotifyDelayUI: ignored in the reference, returns 0.
            t.gpr[3] = 0_u64;
            Ok(())
        }
        (Lib::Xam, 0x28E) => {
            kernel.notify_broadcast(arg(t, 0), arg(t, 1));
            t.gpr[3] = 0_u64;
            Ok(())
        }
        // XamContentGetLicenseMask (reference `am_content.cc`): sync
        // path writes the mask and returns SUCCESS. Bit 0 = full
        // version license for XBLA titles (per the reference `license_mask`
        // docs); this box owns the running title, so bit 0 is set —
        // hardware truth for a purchased title, not the reference's
        // default-deny cvar.
        (Lib::Xam, 0x266) => {
            let mask_ptr = arg(t, 0);
            let overlapped = arg(t, 1);
            if mask_ptr == 0 {
                t.gpr[3] = 0x57_u64; // X_ERROR_INVALID_PARAMETER
                return Ok(());
            }
            if overlapped != 0 {
                // No overlapped completion machinery yet: report
                // pending without writing (documented gap).
                t.gpr[3] = 0x3E5_u64; // X_ERROR_IO_PENDING
                return Ok(());
            }
            mem.write_u32(mask_ptr, 1)?;
            t.gpr[3] = 0_u64;
            Ok(())
        }
        // XGetGameRegion (reference `am_locale.cc`: region table indexed
        // by XCONFIG country; US index 1 yields 0x03FF = NTSC North
        // America, the standard answer for US titles).
        (Lib::Xam, 0x3CC) => {
            t.gpr[3] = 0x03FF_u64;
            Ok(())
        }
        // XMsgInProcessCall(app, message, arg1, arg2) (reference
        // `xam_msg.cc` + `apps/xlivebase_app.cc`): synchronous app
        // dispatch. Only the LiveBase app (0xFC) has verified message
        // decodes; unknown apps return X_E_NOT_FOUND and unknown
        // messages X_E_FAIL, exactly like the reference. No guest
        // memory is touched by the implemented messages.
        (Lib::Xam, 0x1F4) => xmsg_in_process_call(arg(t, 0), arg(t, 1), t),
        // XamPackageManagerGetExperienceMode(out_ptr): no dedicated
        // reference implementation (only usage notes in `am_ui.cc`:
        // caller passes &var with var=1, then treats ret<0 or
        // (var&1)==0 as the no-experience path). Report the
        // full-experience offline answer: write 1, return SUCCESS.
        (Lib::Xam, 0x646) => {
            let out = arg(t, 0);
            if out == 0 {
                t.gpr[3] = 0x57_u64; // X_ERROR_INVALID_PARAMETER
                return Ok(());
            }
            mem.write_u32(out, 1)?;
            t.gpr[3] = 0_u64;
            Ok(())
        }
        // XamUserFlushLogonQueue(...): no reference implementation
        // (table-only `kFunction`). Offline no-op success: the logon
        // queue is empty with no signed-in users, so there is nothing
        // to flush and no guest memory to fill.
        (Lib::Xam, 0x220) => {
            t.gpr[3] = 0_u64;
            Ok(())
        }
        // XamGetLanguage (reference `am_locale.cc` `xeGetLanguage`):
        // XConfig language clamped to the base set, falling back to
        // English (1) for out-of-range values and non-Japanese/Korean
        // regions. Our XConfig defaults read English, so this is 1.
        (Lib::Xam, 0x3D2) => {
            t.gpr[3] = 1_u64;
            Ok(())
        }
        // XamGetLocale (reference `am_locale.cc` `xeXamGetLocale`):
        // XConfig country mapped through the locale table, falling
        // back to the game region. US country + NTSC region yields
        // 36 (US), consistent with the English/0x03FF answers above.
        (Lib::Xam, 0x4A9) => {
            t.gpr[3] = 36_u64;
            Ok(())
        }
        // XamGetOnlineLanguageAndCountry(xuid, lang_ptr, country_ptr)
        // (reference `am_locale.cc`): void; writes the profile (or
        // XConfig fallback) language and country bytes. Offline with
        // no signed-in users: English (1) + US (103), matching the
        // XConfig table.
        (Lib::Xam, 0x58B) => {
            let lang_ptr = arg(t, 1);
            let country_ptr = arg(t, 2);
            if lang_ptr != 0 {
                mem.write_u8(lang_ptr, 1)?;
            }
            if country_ptr != 0 {
                mem.write_u8(country_ptr, 103)?;
            }
            Ok(())
        }
        // XamBackgroundDownloadSetMode(mode): table-only in the
        // reference (no implementation found). Offline no-op success;
        // there is no download backend yet to reconfigure.
        (Lib::Xam, 0x9C4) => {
            t.gpr[3] = 0_u64;
            Ok(())
        }
        // XamBackgroundDownloadNetworkStorageRegisterChangeCallback:
        // table-only in the reference (no implementation found).
        // Offline no-op success; with no storage backend there is
        // nothing whose changes could fire the callback.
        (Lib::Xam, 0x4E4) => {
            t.gpr[3] = 0_u64;
            Ok(())
        }
        // XamGetStagingMode (reference `am_info.cc`): preview-mode
        // flag, default 0 (retail dashboard, no debug rendering).
        (Lib::Xam, 0x76F) => {
            t.gpr[3] = 0_u64;
            Ok(())
        }
        // XGetVideoMode(mode_ptr) (reference `am_video.cc`): same as
        // VdQueryVideoMode (1280x720 HDMI default).
        (Lib::Xam, 0x3D1) => vd_query_video_mode(mem, arg(t, 0), t),
        // XamGetDashBackstackData(data, count) (reference
        // `am_info.cc`): drains queued backstack nodes; with none
        // queued (nothing pushes nodes in this boot) it touches
        // nothing and returns SUCCESS, exactly like the reference.
        (Lib::Xam, 0x7DC) => {
            t.gpr[3] = 0_u64;
            Ok(())
        }
        // XamFitnessClearBodyProfileRecords: table-only in the
        // reference (no implementation found). Offline no-op success;
        // no fitness profiles are stored.
        (Lib::Xam, 0x4C1) => {
            t.gpr[3] = 0_u64;
            Ok(())
        }
        // XamSetDashContext(value) (reference `am_info.cc`): store
        // the dash context word, broadcasting
        // SystemDashContextChanged (0x8000000C) only on change.
        // Returns 0; the privilege check is skipped (all titles run).
        (Lib::Xam, 0x1CC) => {
            let value = arg(t, 0);
            if value != kernel.dash_context {
                kernel.dash_context = value;
                kernel.notify_broadcast(0x8000_000C, 0);
            }
            t.gpr[3] = 0_u64;
            Ok(())
        }
        // XamGetDashContext (reference `am_info.cc`): read the word.
        (Lib::Xam, 0x1CD) => {
            t.gpr[3] = (kernel.dash_context) as u64;
            Ok(())
        }
        // Title launch data (reference `am_info.cc`
        // `XamLoaderSetLaunchData`/`GetLaunchData(Size)`): empty until
        // set; empty reads report NOT_FOUND (2) exactly like the
        // reference, touching no guest memory.
        (Lib::Xam, 0x1A6) => {
            let (data, size) = (arg(t, 0), arg(t, 1) as usize);
            kernel.launch_data.resize(size, 0);
            if size != 0 {
                let b = mem.read_bytes(data, size)?;
                kernel.launch_data.copy_from_slice(b);
            }
            t.gpr[3] = 0_u64;
            Ok(())
        }
        (Lib::Xam, 0x1A7) => {
            let size_ptr = arg(t, 0);
            if size_ptr == 0 {
                t.gpr[3] = 0x57_u64; // X_ERROR_INVALID_PARAMETER
                return Ok(());
            }
            if kernel.launch_data.is_empty() {
                mem.write_u32(size_ptr, 0)?;
                t.gpr[3] = 2_u64; // X_ERROR_NOT_FOUND
                return Ok(());
            }
            mem.write_u32(size_ptr, kernel.launch_data.len() as u32)?;
            t.gpr[3] = 0_u64;
            Ok(())
        }
        (Lib::Xam, 0x1A8) => {
            let (buf, len) = (arg(t, 0), arg(t, 1) as usize);
            if kernel.launch_data.is_empty() {
                t.gpr[3] = 2_u64; // X_ERROR_NOT_FOUND
                return Ok(());
            }
            let n = len.min(kernel.launch_data.len());
            if n != 0 {
                mem.write_bytes(buf, &kernel.launch_data[..n])?;
            }
            t.gpr[3] = 0_u64;
            Ok(())
        }
        // XdfInitialize: table-only in the reference (no
        // implementation found). Offline no-op success; there is no
        // disc-format backend to initialize.
        (Lib::Xam, 0x650) => {
            t.gpr[3] = 0_u64;
            Ok(())
        }
        _ => {
            *table.unimplemented_calls.entry(key.clone()).or_insert(0) += 1;
            let name = ImportTable::name_of(&imp.lib, ord).unwrap_or("?");
            return Err(EmuError::Unsupported(format!(
                "unimplemented import {}!{} ({}) r3={:08x} r4={:08x} r5={:08x} r6={:08x} r7={:08x}",
                imp.lib,
                name,
                ord,
                arg(t, 0),
                arg(t, 1),
                arg(t, 2),
                arg(t, 3),
                arg(t, 4),
            )));
        }
    }?;
    *table.implemented_calls.entry(key).or_insert(0) += 1;
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Lib {
    Xboxkrnl,
    Xam,
    Other,
}

fn lib_kind(lib: &str) -> Lib {
    if lib.contains("xboxkrnl") {
        Lib::Xboxkrnl
    } else if lib == "xam.xex" || lib.contains("xam") {
        Lib::Xam
    } else {
        Lib::Other
    }
}

// ---- Critical sections (single-threaded real semantics) ----

fn rtl_init_cs(
    kernel: &mut Kernel,
    mem: &mut Memory,
    cs: u32,
    spin: u32,
    t: &mut ThreadState,
) -> Result<()> {
    if cs == 0 {
        return Err(EmuError::Other("null critical section".into()));
    }
    let div = ((spin + 255) >> 8).min(255) as u8;
    let mut hdr = [0u8; 16];
    hdr[0] = 1; // EventSynchronizationObject
    hdr[1] = div;
    mem.write_bytes(cs, &hdr)?;
    write_i32be(mem, cs + CS_LOCK, -1)?;
    write_i32be(mem, cs + CS_RECURSION, 0)?;
    mem.write_u32(cs + CS_OWNER, 0)?;
    kernel.crit_insert(cs, div);
    t.gpr[3] = 0_u64;
    Ok(())
}

fn rtl_enter_cs(
    kernel: &mut Kernel,
    mem: &mut Memory,
    thread_id: u32,
    cs: u32,
    t: &mut ThreadState,
) -> Result<()> {
    if cs == 0 {
        return Err(EmuError::Other("null critical section".into()));
    }
    // Tolerate never-initialized sections whose image bytes are zero:
    // treat all-zero as free (reference notes pre-initialized data).
    let lock = read_i32be(mem, cs + CS_LOCK).unwrap_or(-1);
    let owner = mem.read_u32(cs + CS_OWNER).unwrap_or(0);
    if owner == thread_id && lock >= 0 {
        write_i32be(mem, cs + CS_LOCK, lock + 1)?;
        let rec = read_i32be(mem, cs + CS_RECURSION).unwrap_or(0);
        write_i32be(mem, cs + CS_RECURSION, rec + 1)?;
    } else if lock < 0 || owner == 0 {
        write_i32be(mem, cs + CS_LOCK, 0)?;
        write_i32be(mem, cs + CS_RECURSION, 1)?;
        mem.write_u32(cs + CS_OWNER, thread_id)?;
    } else {
        return Err(EmuError::Other(format!(
            "critical section {:08x} owned by another thread",
            cs
        )));
    }
    kernel.crit_owned(cs, thread_id);
    t.gpr[3] = 0_u64;
    Ok(())
}

fn rtl_leave_cs(
    kernel: &mut Kernel,
    mem: &mut Memory,
    thread_id: u32,
    cs: u32,
    t: &mut ThreadState,
) -> Result<()> {
    if cs == 0 {
        return Err(EmuError::Other("null critical section".into()));
    }
    let owner = mem.read_u32(cs + CS_OWNER)?;
    if owner != thread_id {
        return Err(EmuError::Other(format!(
            "leave of unowned critical section {:08x}",
            cs
        )));
    }
    let rec = read_i32be(mem, cs + CS_RECURSION)?;
    if rec <= 1 {
        write_i32be(mem, cs + CS_LOCK, -1)?;
        write_i32be(mem, cs + CS_RECURSION, 0)?;
        mem.write_u32(cs + CS_OWNER, 0)?;
        kernel.crit_released(cs);
    } else {
        let lock = read_i32be(mem, cs + CS_LOCK)?;
        write_i32be(mem, cs + CS_LOCK, lock - 1)?;
        write_i32be(mem, cs + CS_RECURSION, rec - 1)?;
    }
    t.gpr[3] = 0_u64;
    Ok(())
}

fn rtl_try_enter_cs(
    kernel: &mut Kernel,
    mem: &mut Memory,
    thread_id: u32,
    cs: u32,
    t: &mut ThreadState,
) -> Result<()> {
    if cs == 0 {
        t.gpr[3] = 1_u64;
        return Ok(());
    }
    let lock = read_i32be(mem, cs + CS_LOCK).unwrap_or(-1);
    let owner = mem.read_u32(cs + CS_OWNER).unwrap_or(0);
    if lock < 0 || owner == 0 || owner == thread_id {
        rtl_enter_cs(kernel, mem, thread_id, cs, t)?;
        t.gpr[3] = 1_u64;
    } else {
        t.gpr[3] = 0_u64;
    }
    Ok(())
}

// ---- Strings ----

/// `X_ANSI_STRING`: length u16be, max u16be, buffer u32be.
fn rtl_init_ansi(mem: &mut Memory, dst: u32, src: u32, t: &mut ThreadState) -> Result<()> {
    if dst == 0 {
        return Err(EmuError::Other("null ANSI_STRING".into()));
    }
    if src == 0 {
        write_u16be(mem, dst, 0)?;
        write_u16be(mem, dst + 2, 0)?;
        mem.write_u32(dst + 4, 0)?;
    } else {
        let s = read_cstr(mem, src)?;
        if s.len() > 0xFFFF {
            return Err(EmuError::Other("ansi source too long".into()));
        }
        write_u16be(mem, dst, s.len() as u16)?;
        write_u16be(mem, dst + 2, (s.len() + 1) as u16)?;
        mem.write_u32(dst + 4, src)?;
    }
    t.gpr[3] = 0_u64;
    Ok(())
}

/// `X_UNICODE_STRING`: same shape, lengths in bytes over UTF-16 data.
fn rtl_init_unicode(mem: &mut Memory, dst: u32, src: u32, t: &mut ThreadState) -> Result<()> {
    if dst == 0 {
        return Err(EmuError::Other("null UNICODE_STRING".into()));
    }
    if src == 0 {
        write_u16be(mem, dst, 0)?;
        write_u16be(mem, dst + 2, 0)?;
        mem.write_u32(dst + 4, 0)?;
    } else {
        // Count NUL-terminated UTF-16 code units (up to 2048).
        let mut units = 0usize;
        for i in 0..2048usize {
            let u = read_u16be(mem, src + (i as u32) * 2)?;
            if u == 0 {
                break;
            }
            units += 1;
        }
        if units >= 2048 {
            return Err(EmuError::Other("unicode source unterminated".into()));
        }
        let bytes = (units * 2) as u16;
        write_u16be(mem, dst, bytes)?;
        write_u16be(mem, dst + 2, bytes.wrapping_add(2))?;
        mem.write_u32(dst + 4, src)?;
    }
    t.gpr[3] = (dst) as u64;
    Ok(())
}

fn rtl_free_string(mem: &mut Memory, s: u32, t: &mut ThreadState) -> Result<()> {
    if s != 0 {
        write_u16be(mem, s, 0)?;
        write_u16be(mem, s + 2, 0)?;
        mem.write_u32(s + 4, 0)?;
    }
    t.gpr[3] = 0_u64;
    Ok(())
}

/// Copy ANSI (unit 1) or Unicode (unit 2) strings honoring max lengths.
fn rtl_copy_string(
    mem: &mut Memory,
    dst: u32,
    src: u32,
    unit: u32,
    t: &mut ThreadState,
) -> Result<()> {
    if dst == 0 {
        return Err(EmuError::Other("null copy destination".into()));
    }
    if src == 0 {
        write_u16be(mem, dst, 0)?;
        t.gpr[3] = 0_u64;
        return Ok(());
    }
    let src_len = read_u16be(mem, src)? as u32;
    let src_ptr = mem.read_u32(src + 4)?;
    let dst_max = read_u16be(mem, dst + 2)? as u32;
    let dst_buf = mem.read_u32(dst + 4)?;
    let n = src_len.min(dst_max);
    if n > 0 {
        let bytes = mem.read_bytes(src_ptr, (n * unit) as usize)?.to_vec();
        mem.write_bytes(dst_buf, &bytes)?;
    }
    write_u16be(mem, dst, n as u16)?;
    t.gpr[3] = 0_u64;
    Ok(())
}

fn rtl_compare_memory(
    mem: &mut Memory,
    a: u32,
    b: u32,
    len: u32,
    t: &mut ThreadState,
) -> Result<()> {
    if len > 16 * 1024 * 1024 {
        return Err(EmuError::Other("compare length unreasonable".into()));
    }
    let ab = mem.read_bytes(a, len as usize)?.to_vec();
    let bb = mem.read_bytes(b, len as usize)?.to_vec();
    // Report -1/0/1 as u32 like memcmp.
    t.gpr[3] = match ab.cmp(&bb) {
        std::cmp::Ordering::Less => 0xFFFF_FFFF,
        std::cmp::Ordering::Equal => 0,
        std::cmp::Ordering::Greater => 1,
    };
    Ok(())
}

fn rtl_compare_memory_ulong(
    mem: &mut Memory,
    ptr: u32,
    value: u32,
    len: u32,
    t: &mut ThreadState,
) -> Result<()> {
    if !len.is_multiple_of(4) {
        return Err(EmuError::Other("ulong compare length unaligned".into()));
    }
    let pat = value.to_be_bytes();
    for off in (0..len).step_by(4) {
        let w = mem.read_bytes(ptr + off, 4)?;
        if w != pat {
            t.gpr[3] = 1_u64;
            return Ok(());
        }
    }
    t.gpr[3] = 0_u64;
    Ok(())
}

fn rtl_fill_ulong(
    mem: &mut Memory,
    ptr: u32,
    len: u32,
    pattern: u32,
    t: &mut ThreadState,
) -> Result<()> {
    if !len.is_multiple_of(4) {
        return Err(EmuError::Other("fill length unaligned".into()));
    }
    if len > 64 * 1024 * 1024 {
        return Err(EmuError::Other("fill length unreasonable".into()));
    }
    let pat = pattern.to_be_bytes();
    for off in (0..len).step_by(4) {
        mem.write_bytes(ptr + off, &pat)?;
    }
    t.gpr[3] = 0_u64;
    Ok(())
}

// ---- Pool + virtual/physical memory (backed by the kernel heap) ----

fn ex_alloc_pool(
    kernel: &mut Kernel,
    mem: &mut Memory,
    size: u32,
    t: &mut ThreadState,
) -> Result<()> {
    if size == 0 || size > 256 * 1024 * 1024 {
        return Err(EmuError::Other(format!("pool size {} rejected", size)));
    }
    let addr = kernel.alloc_mem(size, 8)?;
    mem.write_bytes(addr, &vec![0u8; size as usize])?;
    t.gpr[3] = (addr) as u64;
    Ok(())
}

fn ex_free_pool(kernel: &mut Kernel, addr: u32, t: &mut ThreadState) -> Result<()> {
    if addr != 0 {
        kernel.free_mem(addr)?;
    }
    t.gpr[3] = 0_u64;
    Ok(())
}

fn ex_query_pool_size(kernel: &Kernel, addr: u32, t: &mut ThreadState) -> Result<()> {
    t.gpr[3] = (kernel.alloc_size(addr)) as u64;
    Ok(())
}

fn page_size_for(alloc_type: u32) -> u32 {
    if alloc_type & MEM_LARGE_PAGES != 0 {
        64 * 1024
    } else {
        4096
    }
}

fn nt_alloc_virt(
    kernel: &mut Kernel,
    mem: &mut Memory,
    base_ptr: u32,
    size_ptr: u32,
    alloc_type: u32,
    _protect: u32,
    t: &mut ThreadState,
) -> Result<()> {
    if base_ptr == 0 || size_ptr == 0 {
        t.gpr[3] = (STATUS_INVALID_PARAMETER) as u64;
        return Ok(());
    }
    if alloc_type & MEM_RESET != 0 && alloc_type & !MEM_RESET != 0 {
        t.gpr[3] = (STATUS_INVALID_PARAMETER) as u64;
        return Ok(());
    }
    if alloc_type & (MEM_COMMIT | MEM_RESERVE | MEM_RESET) == 0 {
        t.gpr[3] = (STATUS_INVALID_PARAMETER) as u64;
        return Ok(());
    }
    let want_base = mem.read_u32(base_ptr)?;
    let want_size = mem.read_u32(size_ptr)? as i32;
    let want_size = if want_size < 0 {
        (-want_size) as u32
    } else {
        want_size as u32
    };
    if want_size == 0 {
        t.gpr[3] = (STATUS_INVALID_PARAMETER) as u64;
        return Ok(());
    }
    let page = page_size_for(alloc_type);
    let size = want_size.div_ceil(page) * page;
    // Fixed-base requests must already be tracked; otherwise bump-allocate.
    let addr = if want_base != 0 {
        let aligned = want_base - (want_base % page);
        if kernel.alloc_size(aligned) == 0 {
            // Not ours: carve it from the heap window if it fits.
            kernel.alloc_mem_at(aligned, size)?
        } else {
            aligned
        }
    } else {
        kernel.alloc_mem(size, page.min(65536))?
    };
    if alloc_type & MEM_COMMIT != 0 && alloc_type & MEM_NOZERO == 0 {
        mem.write_bytes(addr, &vec![0u8; size as usize])?;
    }
    mem.write_u32(base_ptr, addr)?;
    mem.write_u32(size_ptr, size)?;
    t.gpr[3] = (STATUS_SUCCESS) as u64;
    Ok(())
}

fn nt_free_virt(
    kernel: &mut Kernel,
    mem: &mut Memory,
    base_ptr: u32,
    size_ptr: u32,
    _free_type: u32,
    t: &mut ThreadState,
) -> Result<()> {
    if base_ptr == 0 || size_ptr == 0 {
        t.gpr[3] = (STATUS_INVALID_PARAMETER) as u64;
        return Ok(());
    }
    let base = mem.read_u32(base_ptr)?;
    t.gpr[3] = match kernel.free_mem(base) {
        Ok(_) => STATUS_SUCCESS,
        Err(_) => STATUS_INVALID_PARAMETER,
    } as u64;
    Ok(())
}

fn nt_query_virt(
    kernel: &Kernel,
    mem: &mut Memory,
    base: u32,
    info_ptr: u32,
    t: &mut ThreadState,
) -> Result<()> {
    if info_ptr == 0 {
        t.gpr[3] = (STATUS_INVALID_PARAMETER) as u64;
        return Ok(());
    }
    // `X_MEMORY_BASIC_INFORMATION`: 7 x u32be.
    let size = kernel.alloc_size(base);
    if size == 0 {
        t.gpr[3] = (STATUS_INVALID_PARAMETER) as u64;
        return Ok(());
    }
    mem.write_u32(info_ptr, base)?;
    mem.write_u32(info_ptr + 4, base)?;
    mem.write_u32(info_ptr + 8, 0x04)?; // PAGE_READWRITE
    mem.write_u32(info_ptr + 12, size)?;
    mem.write_u32(info_ptr + 16, MEM_COMMIT | MEM_RESERVE)?;
    mem.write_u32(info_ptr + 20, 0x04)?;
    mem.write_u32(info_ptr + 24, 0x0002_0000)?; // MEM_PRIVATE
    t.gpr[3] = (STATUS_SUCCESS) as u64;
    Ok(())
}

fn mm_alloc_phys(
    kernel: &mut Kernel,
    mem: &mut Memory,
    size: u32,
    protect: u32,
    t: &mut ThreadState,
) -> Result<()> {
    let _ = protect;
    if size == 0 {
        t.gpr[3] = 0_u64;
        return Ok(());
    }
    let addr = kernel.alloc_mem(size.div_ceil(4096) * 4096, 4096)?;
    mem.write_bytes(addr, &vec![0u8; (size.div_ceil(4096) * 4096) as usize])?;
    t.gpr[3] = (addr) as u64;
    Ok(())
}

fn mm_alloc_phys_ex(kernel: &mut Kernel, mem: &mut Memory, t: &mut ThreadState) -> Result<()> {
    // (flags, size, protect, min_range, max_range, alignment); range and
    // alignment narrow the placement, which the bump heap honors only by
    // alignment (documented approximation, never silent success).
    let size = arg(t, 1);
    let protect = arg(t, 2);
    let _min = arg(t, 3);
    let _max = arg(t, 4);
    let align = arg(t, 5).max(4096);
    if size == 0 {
        t.gpr[3] = 0_u64;
        return Ok(());
    }
    let rounded = size.div_ceil(4096) * 4096;
    let addr = kernel.alloc_mem(rounded, align.min(65536))?;
    mem.write_bytes(addr, &vec![0u8; rounded as usize])?;
    let _ = protect;
    t.gpr[3] = (addr) as u64;
    Ok(())
}

fn mm_free_phys(kernel: &mut Kernel, addr: u32, t: &mut ThreadState) -> Result<()> {
    if addr != 0 {
        let _ = kernel.free_mem(addr);
    }
    t.gpr[3] = 0_u64;
    Ok(())
}

fn mm_query_alloc_size(kernel: &Kernel, addr: u32, t: &mut ThreadState) -> Result<()> {
    t.gpr[3] = (kernel.alloc_size(addr)) as u64;
    Ok(())
}

// ---- TLS ----

fn ke_tls_alloc(kernel: &mut Kernel, t: &mut ThreadState) -> Result<()> {
    t.gpr[3] = match kernel.tls_alloc() {
        Some(slot) => slot as u64,
        None => 0xFFFF_FFFF, // X_TLS_OUT_OF_INDEXES
    };
    Ok(())
}

fn ke_tls_free(kernel: &mut Kernel, index: u32, t: &mut ThreadState) -> Result<()> {
    if index == 0xFFFF_FFFF {
        t.gpr[3] = 0_u64;
    } else {
        t.gpr[3] = (u32::from(kernel.tls_free(index))) as u64;
    }
    Ok(())
}

fn ke_tls_get(kernel: &Kernel, index: u32, t: &mut ThreadState) -> Result<()> {
    t.gpr[3] = (kernel.tls_get(index)) as u64;
    Ok(())
}

fn ke_tls_set(kernel: &mut Kernel, index: u32, value: u32, t: &mut ThreadState) -> Result<()> {
    t.gpr[3] = (u32::from(kernel.tls_set(index, value))) as u64;
    Ok(())
}

// ---- Time ----

fn guest_uptime_100ns() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    // 100ns ticks since the Unix epoch: real, monotonic-enough clock.
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64 / 100)
        .unwrap_or(0)
}

fn ke_query_system_time(mem: &mut Memory, out_ptr: u32, _t: &mut ThreadState) -> Result<()> {
    if out_ptr == 0 {
        return Err(EmuError::Other("null system-time pointer".into()));
    }
    let now = guest_uptime_100ns();
    mem.write_u32(out_ptr, (now >> 32) as u32)?;
    mem.write_u32(out_ptr + 4, now as u32)?;
    // Returns void in the reference; leave r3 alone.
    Ok(())
}

fn ke_query_perf_freq(mem: &mut Memory, out_ptr: u32, t: &mut ThreadState) -> Result<()> {
    // Xbox timebase: 50 MHz. Returns the frequency in r3 as well as
    // via out_ptr: game wrappers store r3 over the slot (reference
    // `KeQueryPerformanceFrequency_entry` returns the frequency).
    if out_ptr != 0 {
        mem.write_u32(out_ptr, 50_000_000)?;
    }
    t.gpr[3] = 50_000_000_u64;
    Ok(())
}

// ---- NT sync objects (reference `xboxkrnl_threading.cc`,
// `xevent.cc`, `xsemaphore.cc`, `xmutant.cc`; facts only) ----

/// `NtCreateEvent(handle_ptr, attr, event_type, initial)`: type 0 =
/// notification (manual), nonzero = synchronization (auto).
fn nt_create_event(
    kernel: &mut Kernel,
    mem: &mut Memory,
    handle_ptr: u32,
    event_type: u32,
    initial: u32,
    t: &mut ThreadState,
) -> Result<()> {
    // Named objects are not yet matched; every call creates a fresh
    // object (no OBJECT_NAME_EXISTS path until names are parsed).
    match kernel.nt_create_event(mem, event_type, initial != 0) {
        Ok(h) => {
            if handle_ptr != 0 {
                mem.write_u32(handle_ptr, h)?;
            }
            t.gpr[3] = (STATUS_SUCCESS) as u64;
        }
        Err(e) => {
            log::warn!("kernel: NtCreateEvent failed: {}", e);
            if handle_ptr != 0 {
                let _ = mem.write_u32(handle_ptr, 0);
            }
            t.gpr[3] = (STATUS_NO_MEMORY) as u64;
        }
    }
    Ok(())
}

/// `NtCreateSemaphore(handle_ptr, attr, count, limit)`.
fn nt_create_semaphore(
    kernel: &mut Kernel,
    mem: &mut Memory,
    handle_ptr: u32,
    count: u32,
    limit: u32,
    t: &mut ThreadState,
) -> Result<()> {
    match kernel.nt_create_semaphore(mem, count as i32, limit as i32) {
        Ok(h) => {
            if handle_ptr != 0 {
                mem.write_u32(handle_ptr, h)?;
            }
            t.gpr[3] = (STATUS_SUCCESS) as u64;
        }
        Err(e) => {
            let msg = format!("{}", e);
            if handle_ptr != 0 {
                mem.write_u32(handle_ptr, 0)?;
            }
            // Validation failures are INVALID_PARAMETER; allocation
            // failures are NO_MEMORY (message-distinguished, genuine).
            t.gpr[3] = (if msg.contains("bad semaphore") {
                STATUS_INVALID_PARAMETER
            } else {
                STATUS_NO_MEMORY
            }) as u64;
        }
    }
    Ok(())
}

/// `NtCreateMutant(handle_ptr, attr, initial_owner)`.
fn nt_create_mutant(
    kernel: &mut Kernel,
    mem: &mut Memory,
    handle_ptr: u32,
    initial_owner: u32,
    thread_id: u32,
    t: &mut ThreadState,
) -> Result<()> {
    match kernel.nt_create_mutant(mem, initial_owner != 0, thread_id) {
        Ok(h) => {
            if handle_ptr != 0 {
                mem.write_u32(handle_ptr, h)?;
            }
            t.gpr[3] = (STATUS_SUCCESS) as u64;
        }
        Err(e) => {
            log::warn!("kernel: NtCreateMutant failed: {}", e);
            if handle_ptr != 0 {
                let _ = mem.write_u32(handle_ptr, 0);
            }
            t.gpr[3] = (STATUS_NO_MEMORY) as u64;
        }
    }
    Ok(())
}

/// `NtCreateTimer(handle_ptr, attr, timer_type)`.
fn nt_create_timer(
    kernel: &mut Kernel,
    mem: &mut Memory,
    handle_ptr: u32,
    timer_type: u32,
    t: &mut ThreadState,
) -> Result<()> {
    match kernel.nt_create_timer(mem, timer_type) {
        Ok(h) => {
            if handle_ptr != 0 {
                mem.write_u32(handle_ptr, h)?;
            }
            t.gpr[3] = (STATUS_SUCCESS) as u64;
        }
        Err(e) => {
            log::warn!("kernel: NtCreateTimer failed: {}", e);
            if handle_ptr != 0 {
                let _ = mem.write_u32(handle_ptr, 0);
            }
            t.gpr[3] = (STATUS_NO_MEMORY) as u64;
        }
    }
    Ok(())
}

/// Mirror an event's signal state into its guest `X_KEVENT`.
fn mirror_event(kernel: &Kernel, mem: &mut Memory, handle: u32) {
    if let Some(e) = kernel.nt_events.get(&handle) {
        let _ = mem.write_u32(e.guest_ptr + 4, u32::from(e.signaled));
    }
}

/// Mirror a semaphore's count into its guest `X_KSEMAPHORE`.
fn mirror_semaphore(kernel: &Kernel, mem: &mut Memory, handle: u32) {
    if let Some(s) = kernel.nt_semaphores.get(&handle) {
        let _ = mem.write_u32(s.guest_ptr + 4, s.count as u32);
        let _ = mem.write_u32(s.guest_ptr + 0x10, s.limit as u32);
    }
}

/// Mirror a mutant's ownership into its guest `X_KMUTANT`.
fn mirror_mutant(kernel: &Kernel, mem: &mut Memory, handle: u32) {
    if let Some(m) = kernel.nt_mutants.get(&handle) {
        let owned = m.owner.is_some();
        let _ = mem.write_u32(m.guest_ptr + 4, u32::from(!owned));
        let owner_ptr = m
            .owner
            .map(|id| kernel.kthread_of_thread_id(id))
            .unwrap_or(0);
        let _ = mem.write_u32(m.guest_ptr + 0x18, owner_ptr);
    }
}

/// `NtReleaseSemaphore(handle, count, prev_ptr)`.
fn nt_release_semaphore(
    kernel: &mut Kernel,
    mem: &mut Memory,
    handle: u32,
    count: u32,
    prev_ptr: u32,
    t: &mut ThreadState,
) -> Result<()> {
    if !kernel.nt_semaphores.contains_key(&handle) {
        t.gpr[3] = (STATUS_INVALID_HANDLE) as u64;
        return Ok(());
    }
    match kernel.nt_release_semaphore(handle, count as i32) {
        Ok(prev) => {
            if prev_ptr != 0 {
                mem.write_u32(prev_ptr, prev as u32)?;
            }
            mirror_semaphore(kernel, mem, handle);
            t.gpr[3] = (STATUS_SUCCESS) as u64;
        }
        Err(_) => {
            // Reference still reports the current count on overflow.
            let cur = kernel
                .nt_semaphores
                .get(&handle)
                .map(|s| s.count as u32)
                .unwrap_or(0);
            if prev_ptr != 0 {
                mem.write_u32(prev_ptr, cur)?;
            }
            t.gpr[3] = (STATUS_SEMAPHORE_LIMIT_EXCEEDED) as u64;
        }
    }
    Ok(())
}

/// `NtReleaseMutant(handle, prev_ptr?)`: prev is unused by games.
fn nt_release_mutant(
    kernel: &mut Kernel,
    mem: &mut Memory,
    thread_id: u32,
    handle: u32,
    t: &mut ThreadState,
) -> Result<()> {
    if !kernel.nt_mutants.contains_key(&handle) {
        t.gpr[3] = (STATUS_INVALID_HANDLE) as u64;
        return Ok(());
    }
    match kernel.nt_release_mutant(handle, thread_id) {
        Ok(()) => {
            mirror_mutant(kernel, mem, handle);
            t.gpr[3] = (STATUS_SUCCESS) as u64;
        }
        Err(_) => t.gpr[3] = (STATUS_MUTANT_NOT_OWNED) as u64,
    }
    Ok(())
}

/// `NtSetEvent(handle, prev_ptr)`.
fn nt_set_event(
    kernel: &mut Kernel,
    mem: &mut Memory,
    handle: u32,
    prev_ptr: u32,
    t: &mut ThreadState,
) -> Result<()> {
    // Type mismatch (semaphore/mutant handle) is a distinct NTSTATUS
    // in the reference (`xeNtSetEvent` checks the object type).
    if !kernel.nt_events.contains_key(&handle) {
        t.gpr[3] = (if kernel.nt_semaphores.contains_key(&handle)
            || kernel.nt_mutants.contains_key(&handle)
            || kernel.nt_timers.contains_key(&handle)
        {
            STATUS_OBJECT_TYPE_MISMATCH
        } else {
            STATUS_INVALID_HANDLE
        }) as u64;
        return Ok(());
    }
    match kernel.nt_set_event(handle) {
        Ok(prev) => {
            if prev_ptr != 0 {
                mem.write_u32(prev_ptr, prev as u32)?;
            }
            mirror_event(kernel, mem, handle);
            t.gpr[3] = (STATUS_SUCCESS) as u64;
        }
        Err(_) => t.gpr[3] = (STATUS_INVALID_HANDLE) as u64,
    }
    Ok(())
}

/// `NtClearEvent(handle)`.
fn nt_clear_event(
    kernel: &mut Kernel,
    mem: &mut Memory,
    handle: u32,
    t: &mut ThreadState,
) -> Result<()> {
    match kernel.nt_clear_event(handle) {
        Ok(()) => {
            mirror_event(kernel, mem, handle);
            t.gpr[3] = (STATUS_SUCCESS) as u64;
        }
        Err(_) => t.gpr[3] = (STATUS_INVALID_HANDLE) as u64,
    }
    Ok(())
}

/// `NtPulseEvent(handle, prev_ptr)`.
fn nt_pulse_event(
    kernel: &mut Kernel,
    mem: &mut Memory,
    handle: u32,
    prev_ptr: u32,
    t: &mut ThreadState,
) -> Result<()> {
    match kernel.nt_pulse_event(handle) {
        Ok(prev) => {
            if prev_ptr != 0 {
                mem.write_u32(prev_ptr, prev as u32)?;
            }
            mirror_event(kernel, mem, handle);
            t.gpr[3] = (STATUS_SUCCESS) as u64;
        }
        Err(_) => t.gpr[3] = (STATUS_INVALID_HANDLE) as u64,
    }
    Ok(())
}

/// `NtWaitForSingleObjectEx(handle, mode, alertable, timeout_ptr)`:
/// single-threaded poll — acquire when ready, else TIMEOUT. Timeout
/// pointer (guest i64 100ns, NULL = infinite) is honored only as
/// "zero => no wait"; positive waits cannot block without threads.
fn nt_wait_single(
    kernel: &mut Kernel,
    mem: &mut Memory,
    handle: u32,
    thread_id: u32,
    t: &mut ThreadState,
) -> Result<()> {
    match kernel.nt_wait_single(handle, thread_id) {
        Ok(true) => {
            mirror_waited(kernel, mem, handle, thread_id);
            t.gpr[3] = (STATUS_SUCCESS) as u64;
        }
        Ok(false) => t.gpr[3] = (STATUS_TIMEOUT) as u64,
        Err(_) => t.gpr[3] = (STATUS_INVALID_HANDLE) as u64,
    }
    Ok(())
}

/// Mirror whatever `nt_wait_single` just acquired (auto-reset consume,
/// semaphore decrement, mutant own). Manual-reset events and signaled
/// timers need no change.
fn mirror_waited(kernel: &Kernel, mem: &mut Memory, handle: u32, thread_id: u32) {
    if let Some(e) = kernel.nt_events.get(&handle) {
        if !e.manual {
            mirror_event(kernel, mem, handle);
        }
        return;
    }
    if kernel.nt_semaphores.contains_key(&handle) {
        mirror_semaphore(kernel, mem, handle);
        return;
    }
    if kernel.nt_mutants.contains_key(&handle) {
        // Owner may be a fresh acquire; resolve KTHREAD for the guest.
        if let Some(m) = kernel.nt_mutants.get(&handle) {
            let owned = m.owner.is_some();
            let _ = mem.write_u32(m.guest_ptr + 4, u32::from(!owned));
            let owner_ptr = m
                .owner
                .map(|id| kernel.kthread_of_thread_id(id))
                .unwrap_or(0);
            let _ = mem.write_u32(m.guest_ptr + 0x18, owner_ptr);
            let _ = thread_id;
        }
    }
}

/// `NtWaitForMultipleObjectsEx(count, handles_ptr, wait_type, ...)`:
/// wait_type 0 = WaitAll, 1 = WaitAny. Poll semantics matching
/// `nt_wait_single` per object; failed WaitAll consumes nothing.
fn nt_wait_multiple(
    kernel: &mut Kernel,
    mem: &mut Memory,
    count: u32,
    handles_ptr: u32,
    wait_type: u32,
    thread_id: u32,
    t: &mut ThreadState,
) -> Result<()> {
    if count == 0 || count > 64 || handles_ptr == 0 {
        t.gpr[3] = (STATUS_INVALID_PARAMETER) as u64;
        return Ok(());
    }
    let mut handles = Vec::with_capacity(count as usize);
    for i in 0..count {
        let h = mem.read_u32(handles_ptr.wrapping_add(i * 4))?;
        handles.push(h);
    }
    for h in &handles {
        if !kernel.nt_events.contains_key(h)
            && !kernel.nt_semaphores.contains_key(h)
            && !kernel.nt_mutants.contains_key(h)
            && !kernel.nt_timers.contains_key(h)
            && !kernel.nt_threads.contains_key(h)
            && !kernel.files.contains(*h)
        {
            t.gpr[3] = (STATUS_INVALID_HANDLE) as u64;
            return Ok(());
        }
    }
    if wait_type == 1 {
        // WaitAny: first ready object wins.
        for h in handles {
            if kernel.nt_wait_single(h, thread_id).unwrap_or(false) {
                mirror_waited(kernel, mem, h, thread_id);
                t.gpr[3] = (STATUS_SUCCESS) as u64;
                return Ok(());
            }
        }
        t.gpr[3] = (STATUS_TIMEOUT) as u64;
        return Ok(());
    }
    // WaitAll: all must be ready; snapshot first so a partial set is
    // never consumed.
    let ready: Vec<bool> = handles
        .iter()
        .map(|h| {
            if let Some(e) = kernel.nt_events.get(h) {
                e.signaled
            } else if let Some(s) = kernel.nt_semaphores.get(h) {
                s.count > 0
            } else if let Some(m) = kernel.nt_mutants.get(h) {
                m.owner.is_none() || m.owner == Some(thread_id)
            } else if let Some(tm) = kernel.nt_timers.get(h) {
                tm.signaled
            } else if let Some(th) = kernel.nt_threads.get(h) {
                th.exited
            } else {
                false
            }
        })
        .collect();
    if ready.iter().all(|r| *r) {
        for h in handles {
            let _ = kernel.nt_wait_single(h, thread_id);
            mirror_waited(kernel, mem, h, thread_id);
        }
        t.gpr[3] = (STATUS_SUCCESS) as u64;
    } else {
        t.gpr[3] = (STATUS_TIMEOUT) as u64;
    }
    Ok(())
}

// ---- NT threads (reference `ExCreateThread` / `NtResumeThread` /
// `NtSuspendThread` / `ExTerminateThread`; facts only) ----

/// `ExCreateThread(handle_ptr, stack_size, thread_id_ptr,
/// xapi_startup, start_addr, start_context, flags)`.
#[allow(clippy::too_many_arguments)]
fn ex_create_thread(
    kernel: &mut Kernel,
    mem: &mut Memory,
    handle_ptr: u32,
    stack_size: u32,
    thread_id_ptr: u32,
    xapi_startup: u32,
    start_addr: u32,
    start_context: u32,
    flags: u32,
    t: &mut ThreadState,
) -> Result<()> {
    let _ = xapi_startup;
    if start_addr == 0 {
        if handle_ptr != 0 {
            mem.write_u32(handle_ptr, 0)?;
        }
        t.gpr[3] = (STATUS_INVALID_PARAMETER) as u64;
        return Ok(());
    }
    match kernel.ex_create_thread(mem, stack_size, start_addr, start_context, flags) {
        Ok((handle, thread_id, kthread)) => {
            // ReturnKThreadPtr (0x80) returns the KTHREAD address
            // instead of the object handle (reference `ExCreateThread`).
            if handle_ptr != 0 {
                if flags & 0x80 != 0 {
                    mem.write_u32(handle_ptr, kthread)?;
                } else {
                    mem.write_u32(handle_ptr, handle)?;
                }
            }
            if thread_id_ptr != 0 {
                mem.write_u32(thread_id_ptr, thread_id)?;
            }
            t.gpr[3] = (STATUS_SUCCESS) as u64;
        }
        Err(e) => {
            if handle_ptr != 0 {
                let _ = mem.write_u32(handle_ptr, 0);
            }
            log::warn!("kernel: ExCreateThread failed: {}", e);
            t.gpr[3] = (STATUS_NO_MEMORY) as u64;
        }
    }
    Ok(())
}

/// `NtResumeThread(handle, prev_ptr)`.
fn nt_resume_thread(
    kernel: &mut Kernel,
    mem: &mut Memory,
    handle: u32,
    prev_ptr: u32,
    t: &mut ThreadState,
) -> Result<()> {
    // Resume also accepts sync-object handles in NT (no-op when
    // already signaled); threads are the only ones with counts here.
    if let Some(th) = kernel.nt_threads.get(&handle) {
        let _ = th;
        match kernel.nt_resume_thread(mem, handle) {
            Ok(prev) => {
                if prev_ptr != 0 {
                    mem.write_u32(prev_ptr, prev)?;
                }
                t.gpr[3] = (STATUS_SUCCESS) as u64;
            }
            Err(_) => t.gpr[3] = (STATUS_INVALID_HANDLE) as u64,
        }
        return Ok(());
    }
    // Non-thread handles: succeed only for known objects.
    if kernel.nt_events.contains_key(&handle)
        || kernel.nt_semaphores.contains_key(&handle)
        || kernel.nt_mutants.contains_key(&handle)
        || kernel.nt_timers.contains_key(&handle)
    {
        t.gpr[3] = (STATUS_OBJECT_TYPE_MISMATCH) as u64;
    } else {
        t.gpr[3] = (STATUS_INVALID_HANDLE) as u64;
    }
    Ok(())
}

/// `NtSuspendThread(handle, prev_ptr)`.
fn nt_suspend_thread(
    kernel: &mut Kernel,
    mem: &mut Memory,
    handle: u32,
    prev_ptr: u32,
    t: &mut ThreadState,
) -> Result<()> {
    match kernel.nt_suspend_thread(mem, handle) {
        Ok(prev) => {
            if prev_ptr != 0 {
                mem.write_u32(prev_ptr, prev)?;
            }
            t.gpr[3] = (STATUS_SUCCESS) as u64;
        }
        Err(_) => {
            t.gpr[3] = (if kernel.nt_events.contains_key(&handle)
                || kernel.nt_semaphores.contains_key(&handle)
                || kernel.nt_mutants.contains_key(&handle)
                || kernel.nt_timers.contains_key(&handle)
            {
                STATUS_OBJECT_TYPE_MISMATCH
            } else {
                STATUS_INVALID_HANDLE
            }) as u64;
        }
    }
    Ok(())
}

/// `ExTerminateThread(exit_code)`: ends the calling thread. Tracked NT
/// threads are marked exited; the initial boot thread maps to process
/// exit, surfaced as an explicit error the runner reports (never a
/// silent continue).
fn ex_terminate_thread(
    kernel: &mut Kernel,
    thread_id: u32,
    exit_code: u32,
    t: &mut ThreadState,
) -> Result<()> {
    match kernel.ex_terminate_thread(thread_id, exit_code) {
        Ok(false) => {
            t.gpr[3] = (STATUS_SUCCESS) as u64;
            Ok(())
        }
        Ok(true) => Err(EmuError::Other(format!(
            "initial thread terminated with code {:08x}",
            exit_code
        ))),
        Err(e) => Err(e),
    }
}

// ---- Object manager (reference `xboxkrnl_ob.cc`; facts only) ----

/// `ObReferenceObjectByHandle(handle, type_ptr, out_ptr)`: resolve a
/// tracked handle to its guest object pointer. `out_ptr` is zeroed
/// first (reference pre-inits it). The type check is skipped until
/// `X_OBJECT_TYPE` structs are materialized (type variables are
/// currently zeroed cells, so any comparison would false-mismatch);
/// unknown handles still report `INVALID_HANDLE` genuinely.
fn ob_reference_by_handle(
    kernel: &mut Kernel,
    mem: &mut Memory,
    handle: u32,
    type_ptr: u32,
    out_ptr: u32,
    t: &mut ThreadState,
) -> Result<()> {
    let _ = type_ptr;
    if out_ptr != 0 {
        mem.write_u32(out_ptr, 0)?;
    } else {
        // Reference still validates the handle even with null out.
        if kernel.nt_guest_object(handle).is_none() {
            t.gpr[3] = (STATUS_INVALID_HANDLE) as u64;
            return Ok(());
        }
        t.gpr[3] = (STATUS_SUCCESS) as u64;
        return Ok(());
    }
    let Some(native) = kernel.nt_guest_object(handle) else {
        t.gpr[3] = (STATUS_INVALID_HANDLE) as u64;
        return Ok(());
    };
    mem.write_u32(out_ptr, native)?;
    t.gpr[3] = (STATUS_SUCCESS) as u64;
    Ok(())
}

/// `ObLookupThreadByThreadId(id, out_ptr)` (and Any variant): resolve
/// an NT thread id to its KTHREAD pointer.
fn ob_lookup_thread(
    kernel: &Kernel,
    mem: &mut Memory,
    thread_id: u32,
    out_ptr: u32,
    t: &mut ThreadState,
) -> Result<()> {
    let kthread = kernel.kthread_of_thread_id(thread_id);
    if kthread == 0 {
        if out_ptr != 0 {
            mem.write_u32(out_ptr, 0)?;
        }
        t.gpr[3] = (STATUS_INVALID_HANDLE) as u64;
        return Ok(());
    }
    if out_ptr != 0 {
        mem.write_u32(out_ptr, kthread)?;
    }
    t.gpr[3] = (STATUS_SUCCESS) as u64;
    Ok(())
}

// ---- Ke* thread APIs (reference `xboxkrnl_threading.cc`; facts only) ----

/// Resolve a guest thread pointer to its handle (must be a thread).
fn thread_handle_of_ptr(kernel: &Kernel, ptr: u32) -> Option<u32> {
    match kernel.nt_handle_of_guest(ptr) {
        Some((h, "thread")) => Some(h),
        _ => None,
    }
}

/// `KeSetAffinityThread(thread_ptr, affinity, prev_ptr)`: affinity 0
/// is INVALID_PARAMETER; unknown pointers are INVALID_HANDLE.
/// Records the mask; active CPU follows the lowest set bit
/// (reference `GetFakeCpuNumber` maps mask to CPU).
fn ke_set_affinity(
    kernel: &mut Kernel,
    mem: &mut Memory,
    thread_ptr: u32,
    affinity: u32,
    prev_ptr: u32,
    t: &mut ThreadState,
) -> Result<()> {
    if affinity == 0 {
        t.gpr[3] = (STATUS_INVALID_PARAMETER) as u64;
        return Ok(());
    }
    let Some(h) = thread_handle_of_ptr(kernel, thread_ptr) else {
        t.gpr[3] = (STATUS_INVALID_HANDLE) as u64;
        return Ok(());
    };
    let prev = kernel
        .nt_threads
        .get(&h)
        .map(|th| 1u32 << th.active_cpu)
        .unwrap_or(1);
    if let Some(th) = kernel.nt_threads.get_mut(&h) {
        th.affinity = affinity;
        th.active_cpu = affinity.trailing_zeros().min(5) as u8;
        let cpu = th.active_cpu;
        let kthread = th.kthread_ptr;
        let _ = mem.write_u8(kthread + 0xBF, cpu);
    }
    if prev_ptr != 0 {
        mem.write_u32(prev_ptr, prev)?;
    }
    t.gpr[3] = (STATUS_SUCCESS) as u64;
    Ok(())
}

/// `KeQueryBasePriorityThread(thread_ptr)`: returns the priority.
fn ke_query_priority(kernel: &Kernel, thread_ptr: u32, t: &mut ThreadState) -> Result<()> {
    match thread_handle_of_ptr(kernel, thread_ptr).and_then(|h| kernel.nt_threads.get(&h)) {
        Some(th) => t.gpr[3] = (th.priority as u64) & 0xFFFF_FFFF,
        None => t.gpr[3] = 0_u64,
    }
    Ok(())
}

/// `KeSetBasePriorityThread(thread_ptr, increment)`: absolute set
/// clamped at 0 (reference `XThread::SetPriority`); returns previous.
fn ke_set_priority(
    kernel: &mut Kernel,
    mem: &mut Memory,
    thread_ptr: u32,
    increment: u32,
    t: &mut ThreadState,
) -> Result<()> {
    let Some(h) = thread_handle_of_ptr(kernel, thread_ptr) else {
        t.gpr[3] = 0_u64;
        return Ok(());
    };
    let prev = kernel.nt_threads.get(&h).map(|th| th.priority).unwrap_or(0);
    // Signed increment: negative values arrive as u32 (reference
    // clamps negatives to 0).
    let new_prio = (increment as i32).max(0);
    if let Some(th) = kernel.nt_threads.get_mut(&h) {
        th.priority = new_prio;
        let kthread = th.kthread_ptr;
        let _ = mem.write_u8(kthread + 0x70, new_prio.clamp(0, 255) as u8);
        let _ = mem.write_u8(kthread + 0xB9, new_prio.clamp(0, 255) as u8);
    }
    t.gpr[3] = (prev as u64) & 0xFFFF_FFFF;
    Ok(())
}

/// `KeSetDisableBoostThread(thread_ptr, disabled)`: exchanges the
/// boost flag, returns the old value.
fn ke_set_boost(
    kernel: &mut Kernel,
    mem: &mut Memory,
    thread_ptr: u32,
    disabled: u32,
    t: &mut ThreadState,
) -> Result<()> {
    let Some(h) = thread_handle_of_ptr(kernel, thread_ptr) else {
        t.gpr[3] = 0_u64;
        return Ok(());
    };
    let prev = kernel
        .nt_threads
        .get(&h)
        .map(|th| th.boost_disabled)
        .unwrap_or(0);
    if let Some(th) = kernel.nt_threads.get_mut(&h) {
        th.boost_disabled = (disabled & 0xFF) as u8;
        let kthread = th.kthread_ptr;
        let _ = mem.write_u8(kthread + 0xBB, (disabled & 0xFF) as u8);
    }
    t.gpr[3] = (prev) as u64;
    Ok(())
}

/// `KeResumeThread(thread_ptr)`: resume by pointer.
fn ke_resume_ptr(
    kernel: &mut Kernel,
    mem: &mut Memory,
    thread_ptr: u32,
    t: &mut ThreadState,
) -> Result<()> {
    let Some(h) = thread_handle_of_ptr(kernel, thread_ptr) else {
        t.gpr[3] = (STATUS_INVALID_HANDLE) as u64;
        return Ok(());
    };
    match kernel.nt_resume_thread(mem, h) {
        Ok(_) => t.gpr[3] = (STATUS_SUCCESS) as u64,
        Err(_) => t.gpr[3] = (STATUS_INVALID_HANDLE) as u64,
    }
    Ok(())
}

/// `KeSuspendThread(thread_ptr)`: returns the previous suspend count.
fn ke_suspend_ptr(
    kernel: &mut Kernel,
    mem: &mut Memory,
    thread_ptr: u32,
    t: &mut ThreadState,
) -> Result<()> {
    let Some(h) = thread_handle_of_ptr(kernel, thread_ptr) else {
        t.gpr[3] = 0_u64;
        return Ok(());
    };
    match kernel.nt_suspend_thread(mem, h) {
        Ok(prev) => t.gpr[3] = (prev) as u64,
        Err(_) => t.gpr[3] = 0_u64,
    }
    Ok(())
}

/// `KeDelayExecutionThread(mode, alertable, interval_ptr)`:
/// single-threaded: no APCs to process, no scheduler to block on —
/// report SUCCESS immediately (documented approximation; a real
/// delay cannot elapse without preemption).
fn ke_delay_thread(
    _mem: &mut Memory,
    _mode: u32,
    _alertable: u32,
    interval_ptr: u32,
    t: &mut ThreadState,
) -> Result<()> {
    let _ = interval_ptr;
    t.gpr[3] = (STATUS_SUCCESS) as u64;
    Ok(())
}

// ---- XConfig (reference `xboxkrnl_xconfig.cc` / `xconfig.cc` +
// `xconfig.h`; values are the reference `SetDefaults`, sizes are the
// struct field sizes; facts only) ----

/// Default bytes for a known (category, setting), big-endian as the
/// guest expects. `None` = unknown to this shim (reference then
/// reports required size 0 with SUCCESS, buffer untouched).
fn xconfig_default(category: u16, setting: u16) -> Option<Vec<u8>> {
    match (category, setting) {
        // USER (0x03).
        (0x03, 0x09) => Some(1u32.to_be_bytes().to_vec()), // language = English
        (0x03, 0x0A) => Some(0u32.to_be_bytes().to_vec()), // video_flags = RatioNormal
        (0x03, 0x0B) => Some(0x0001_0001u32.to_be_bytes().to_vec()), // audio = DD|DPL
        (0x03, 0x0C) => Some(0x0000_0040u32.to_be_bytes().to_vec()), // retail = DashboardInit
        (0x03, 0x0D) => Some(0u32.to_be_bytes().to_vec()), // devkit_flags
        (0x03, 0x0E) => Some(vec![103u8]),                 // country = US
        (0x03, 0x0F) => Some(vec![0x03u8]),                // parental flags = XBL|Creation
        (0x03, 0x11) => Some(0u64.to_be_bytes().to_vec()), // live_puid
        (0x03, 0x16) => Some(0x0000_00FFu32.to_be_bytes().to_vec()), // pc_game = none
        (0x03, 0x1F) => Some(0.7f32.to_be_bytes().to_vec()), // music_volume
        // SECURED (0x02). av_region is the reference default
        // (`X_AV_REGION::NTSCM`); game/dvd regions are hardware truth
        // for a US box, consistent with country=US and XGetGameRegion.
        (0x02, 0x02) => Some(0x0040_0100u32.to_be_bytes().to_vec()), // av_region = NTSCM
        (0x02, 0x03) => Some(0x03FFu32.to_be_bytes().to_vec()),      // game_region = N. America
        (0x02, 0x04) => Some(1u32.to_be_bytes().to_vec()),           // dvd_region = Region 1
        _ => None,
    }
}

/// `ExGetXConfigSetting(category, setting, buffer, size, req_ptr)`.
fn ex_get_xconfig(
    mem: &mut Memory,
    category: u16,
    setting: u16,
    buffer: u32,
    buffer_size: u16,
    required_ptr: u32,
    t: &mut ThreadState,
) -> Result<()> {
    if buffer == 0 && buffer_size != 0 {
        t.gpr[3] = (STATUS_INVALID_PARAMETER_3) as u64;
        return Ok(());
    }
    let Some(def) = xconfig_default(category, setting) else {
        // Reference: unknown setting reads nothing, required size 0,
        // still SUCCESS.
        if required_ptr != 0 {
            write_u16be(mem, required_ptr, 0)?;
        }
        t.gpr[3] = (STATUS_SUCCESS) as u64;
        return Ok(());
    };
    let size = def.len() as u16;
    if buffer != 0 {
        if buffer_size < size {
            // Reference returns BUFFER_TOO_SMALL without touching the
            // buffer; the entry still reports required size 0 (local
            // never assigned). Mirror both.
            if required_ptr != 0 {
                write_u16be(mem, required_ptr, 0)?;
            }
            t.gpr[3] = (STATUS_BUFFER_TOO_SMALL) as u64;
            return Ok(());
        }
        mem.write_bytes(buffer, &def)?;
    }
    if required_ptr != 0 {
        write_u16be(mem, required_ptr, size)?;
    }
    t.gpr[3] = (STATUS_SUCCESS) as u64;
    Ok(())
}

// ---- File system (reference `xboxkrnl_io.cc`, `xfile.cc`,
// `kernel.h`, `vfs/*`; facts only) ----

/// `ObCreateSymbolicLink(path_ansi, target_ansi)`: register the
/// canonical path -> target mapping. Returns SUCCESS (0); the only
/// failure mode (register error) cannot trigger with a HashMap
/// backend, so success is genuine, not faked.
fn ob_create_symlink(
    kernel: &mut Kernel,
    mem: &Memory,
    path_ptr: u32,
    target_ptr: u32,
    t: &mut ThreadState,
) -> Result<()> {
    let mut path = String::from_utf8_lossy(&read_ansi_bytes(mem, path_ptr)?).to_ascii_lowercase();
    let target = String::from_utf8_lossy(&read_ansi_bytes(mem, target_ptr)?).to_ascii_lowercase();
    for prefix in ["\\??\\", "\\system??\\"] {
        if let Some(stripped) = path.strip_prefix(prefix) {
            path = stripped.to_string();
            break;
        }
    }
    kernel.symlinks.insert(path, target);
    t.gpr[3] = 0_u64;
    Ok(())
}

/// Read a guest `X_ANSI_STRING` (length bytes at pointer).
fn read_ansi_bytes(mem: &Memory, ptr: u32) -> Result<Vec<u8>> {
    if ptr == 0 {
        return Err(EmuError::Other("null ansi string".into()));
    }
    let hdr = mem.read_bytes(ptr, 8)?;
    let len = u16::from_be_bytes([hdr[0], hdr[1]]) as usize;
    if len > 4096 {
        return Err(EmuError::Other("ansi string too long".into()));
    }
    let buf = u32::from_be_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]);
    if buf == 0 && len != 0 {
        return Err(EmuError::Other("null ansi buffer".into()));
    }
    if len == 0 {
        return Ok(Vec::new());
    }
    Ok(mem.read_bytes(buf, len)?.to_vec())
}

/// Write an `X_IO_STATUS_BLOCK` (status u32 + information u32).
fn write_iosb(mem: &mut Memory, ptr: u32, status: u32, info: u32) -> Result<()> {
    if ptr == 0 {
        return Ok(());
    }
    mem.write_u32(ptr, status)?;
    mem.write_u32(ptr + 4, info)?;
    Ok(())
}

/// Failed-open epilogue (reference: `*handle_out = INVALID_HANDLE`,
/// IOSB carries the status, r3 carries the status).
fn fail_open(
    mem: &mut Memory,
    handle_out: u32,
    iosb_ptr: u32,
    status: u32,
    t: &mut ThreadState,
) -> Result<()> {
    use crate::fs::INVALID_HANDLE_VALUE;
    if handle_out != 0 {
        mem.write_u32(handle_out, INVALID_HANDLE_VALUE)?;
    }
    write_iosb(mem, iosb_ptr, status, 0)?;
    t.gpr[3] = (status) as u64;
    Ok(())
}

/// Shared NtCreateFile/NtOpenFile core. `file_attr`/`share` are
/// accepted and ignored (single-user read-only backend, documented).
#[allow(clippy::too_many_arguments)]
fn nt_create_file(
    kernel: &mut Kernel,
    mem: &mut Memory,
    handle_out: u32,
    desired_access: u32,
    attrs_ptr: u32,
    iosb_ptr: u32,
    _file_attr: u32,
    _share: u32,
    disposition: u32,
    options: u32,
    t: &mut ThreadState,
) -> Result<()> {
    use crate::fs::{
        normalize_guest_path, ROOT_DOS_DEVICES, STATUS_ACCESS_DENIED, STATUS_OBJECT_NAME_INVALID,
        STATUS_OBJECT_PATH_NOT_FOUND,
    };
    // The reference rejects a null attribute block outright.
    if attrs_ptr == 0 {
        t.gpr[3] = (STATUS_INVALID_PARAMETER) as u64;
        return Ok(());
    }
    let root = mem.read_u32(attrs_ptr)?;
    let name_ptr = mem.read_u32(attrs_ptr + 4)?;
    // Relative opens resolve against an open directory handle.
    let mut base: Option<String> = None;
    if root != ROOT_DOS_DEVICES && root != 0 {
        match kernel.files.get(root) {
            Some(f) if f.is_dir => base = Some(f.path.clone()),
            _ => {
                return fail_open(mem, handle_out, iosb_ptr, STATUS_INVALID_HANDLE, t);
            }
        }
    }
    let raw = read_ansi_bytes(mem, name_ptr).unwrap_or_default();
    let path = match normalize_guest_path(&raw, base.as_deref()) {
        Ok(p) => p,
        Err(status) => {
            return fail_open(mem, handle_out, iosb_ptr, status, t);
        }
    };
    let Some(backend) = kernel.guest_fs.clone() else {
        return fail_open(mem, handle_out, iosb_ptr, STATUS_OBJECT_PATH_NOT_FOUND, t);
    };
    // Enforce ASCII like the reference (IsValidPath rejects >=127;
    // normalize already rejected, this is the belt).
    if !path.is_ascii() {
        return fail_open(mem, handle_out, iosb_ptr, STATUS_OBJECT_NAME_INVALID, t);
    }
    let lookup = backend.lookup(&path);
    // Read-only backend: write intents are ACCESS_DENIED (reference
    // create-fails), checked after the disposition table resolves.
    let write_wanted = desired_access
        & (crate::fs::ACCESS_GENERIC_WRITE
            | crate::fs::ACCESS_WRITE_DATA
            | crate::fs::ACCESS_APPEND_DATA)
        != 0;
    match kernel.file_open(path.clone(), lookup, disposition, options) {
        Ok((handle, action)) => {
            if write_wanted {
                kernel.files.remove(handle);
                return fail_open(mem, handle_out, iosb_ptr, STATUS_ACCESS_DENIED, t);
            }
            if handle_out != 0 {
                mem.write_u32(handle_out, handle)?;
            }
            write_iosb(mem, iosb_ptr, STATUS_SUCCESS, action)?;
            log::info!(
                "kernel: opened {} -> handle {:08x} (action {})",
                path,
                handle,
                action
            );
            t.gpr[3] = (STATUS_SUCCESS) as u64;
            Ok(())
        }
        Err(status) => fail_open(mem, handle_out, iosb_ptr, status, t),
    }
}

/// `NtReadFile(handle, event, apc_routine, apc_ctx, iosb, buf, len,
/// offset_ptr)`: always completes synchronously (reference takes the
/// sync path unconditionally); non-synchronous opens report PENDING
/// with valid IOSB (reference `!synchronous && != END_OF_FILE`).
/// APC delivery has no mechanism yet: a nonzero routine is logged
/// and skipped (documented), the bytes are still delivered.
#[allow(clippy::too_many_arguments)]
fn nt_read_file(
    kernel: &mut Kernel,
    mem: &mut Memory,
    handle: u32,
    event: u32,
    apc_routine: u32,
    _apc_ctx: u32,
    iosb_ptr: u32,
    buf: u32,
    len: u32,
    offset_ptr: u32,
    t: &mut ThreadState,
) -> Result<()> {
    if event != 0 && !kernel.nt_events.contains_key(&event) {
        write_iosb(mem, iosb_ptr, STATUS_INVALID_HANDLE, 0)?;
        t.gpr[3] = (STATUS_INVALID_HANDLE) as u64;
        return Ok(());
    }
    if !kernel.files.contains(handle) {
        write_iosb(mem, iosb_ptr, STATUS_INVALID_HANDLE, 0)?;
        t.gpr[3] = (STATUS_INVALID_HANDLE) as u64;
        return Ok(());
    }
    let offset = if offset_ptr != 0 {
        Some(mem.read_u64(offset_ptr)?)
    } else {
        None
    };
    match kernel.file_read(handle, len as u64, offset) {
        Ok((data, start, n, status)) => {
            if n > 0 {
                mem.write_bytes(buf, &data[start as usize..start as usize + n])?;
            }
            write_iosb(mem, iosb_ptr, status, n as u32)?;
            if event != 0 {
                let _ = kernel.nt_set_event(event);
                mirror_event(kernel, mem, event);
            }
            if apc_routine & !1 != 0 {
                log::warn!(
                    "kernel: NtReadFile APC {:08x} skipped (no APC delivery yet)",
                    apc_routine & !1
                );
            }
            let sync = kernel
                .files
                .get(handle)
                .map(|f| f.synchronous)
                .unwrap_or(true);
            if !sync && status != crate::fs::STATUS_END_OF_FILE && status == STATUS_SUCCESS {
                t.gpr[3] = (STATUS_PENDING) as u64;
            } else {
                t.gpr[3] = (status) as u64;
            }
            Ok(())
        }
        Err(status) => {
            write_iosb(mem, iosb_ptr, status, 0)?;
            t.gpr[3] = (status) as u64;
            Ok(())
        }
    }
}

/// `NtClose(handle)`: files are released; other tracked NT objects
/// release a reference and stay valid; unknown handles are
/// INVALID_HANDLE (reference `ReleaseHandle`).
fn nt_close_file(kernel: &mut Kernel, handle: u32, t: &mut ThreadState) -> Result<()> {
    if kernel.files.remove(handle) {
        t.gpr[3] = (STATUS_SUCCESS) as u64;
        return Ok(());
    }
    if kernel.nt_guest_object(handle).is_some()
        || kernel.nt_events.contains_key(&handle)
        || kernel.nt_semaphores.contains_key(&handle)
        || kernel.nt_mutants.contains_key(&handle)
        || kernel.nt_timers.contains_key(&handle)
        || kernel.nt_threads.contains_key(&handle)
    {
        t.gpr[3] = (STATUS_SUCCESS) as u64;
        return Ok(());
    }
    t.gpr[3] = (STATUS_INVALID_HANDLE) as u64;
    Ok(())
}

/// FNV-1a/64 for stable file index numbers (deterministic across
/// runs, unlike SipHash).
fn fnv1a_64(s: &str) -> u64 {
    let mut h: u64 = 0xCBF2_9CE4_8422_2325;
    for b in s.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x0100_0000_01B3);
    }
    h
}

// FileInformationClass values (reference `info/file.h`).
const INFO_INTERNAL: u32 = 6;
const INFO_POSITION: u32 = 14;
const INFO_XCTD: u32 = 27;
const INFO_NETWORK_OPEN: u32 = 34;
const INFO_MODE: u32 = 16;
const INFO_ALIGNMENT: u32 = 17;
const INFO_SECTOR: u32 = 26;
const INFO_IOPRIORITY: u32 = 32;
const INFO_NAME: u32 = 9;
const INFO_ALLOCATION: u32 = 19;
const INFO_BASIC: u32 = 4;

/// `NtQueryInformationFile(handle, iosb, info, len, class)`
/// (reference `xboxkrnl_io_info.cc`). Length/handle/class failures
/// return before touching the buffer or IOSB, exactly like the
/// reference. Supported: Internal (path hash), Position (live
/// offset), NetworkOpen (size/attrs, zero times — the read-only
/// backend carries no timestamps).
#[allow(clippy::too_many_arguments)]
fn nt_query_info_file(
    kernel: &mut Kernel,
    mem: &mut Memory,
    handle: u32,
    iosb_ptr: u32,
    info_ptr: u32,
    info_len: u32,
    class: u32,
    t: &mut ThreadState,
) -> Result<()> {
    let min_len = match class {
        INFO_INTERNAL => 8,
        INFO_POSITION => 8,
        INFO_XCTD => 4,
        INFO_NETWORK_OPEN => 56,
        INFO_MODE | INFO_ALIGNMENT | INFO_SECTOR | INFO_IOPRIORITY => 4,
        INFO_NAME | INFO_ALLOCATION => 8,
        INFO_BASIC => 40,
        _ => 0,
    };
    if min_len == 0 {
        t.gpr[3] = (STATUS_INVALID_INFO_CLASS) as u64;
        return Ok(());
    }
    if info_len < min_len {
        t.gpr[3] = (STATUS_INFO_LENGTH_MISMATCH) as u64;
        return Ok(());
    }
    let Some(f) = kernel.files.get(handle) else {
        t.gpr[3] = (STATUS_INVALID_HANDLE) as u64;
        return Ok(());
    };
    let (status, out_len) = match class {
        INFO_INTERNAL => {
            let idx = fnv1a_64(&f.path);
            mem.write_bytes(info_ptr, &vec![0u8; info_len as usize])?;
            mem.write_u64(info_ptr, idx)?;
            (STATUS_SUCCESS, 8)
        }
        INFO_POSITION => {
            let pos = f.pos;
            mem.write_bytes(info_ptr, &vec![0u8; info_len as usize])?;
            mem.write_u64(info_ptr, pos)?;
            (STATUS_SUCCESS, 8)
        }
        INFO_NETWORK_OPEN => {
            let size = f.data.as_ref().map(|d| d.len() as u64).unwrap_or(0);
            let attrs = if f.is_dir { 0x10u32 } else { 0x80u32 };
            mem.write_bytes(info_ptr, &vec![0u8; info_len as usize])?;
            // times (4x u64) stay zero: no timestamps on this backend.
            mem.write_u64(info_ptr + 32, size)?; // allocation_size
            mem.write_u64(info_ptr + 40, size)?; // end_of_file
            mem.write_u32(info_ptr + 48, attrs)?;
            mem.write_u32(info_ptr + 52, 0)?; // pad
            (STATUS_SUCCESS, 56)
        }
        // Reference: XCTD and the length-only classes land in the
        // default arm -> INVALID_PARAMETER with zero output.
        _ => {
            mem.write_bytes(info_ptr, &vec![0u8; info_len as usize])?;
            (STATUS_INVALID_PARAMETER, 0)
        }
    };
    write_iosb(mem, iosb_ptr, status, out_len)?;
    t.gpr[3] = (status) as u64;
    Ok(())
}

// ---- Module queries ----

/// `VdQueryVideoMode(mode_ptr)`: fills `X_VIDEO_MODE` (48 bytes).
fn vd_query_video_mode(mem: &mut Memory, ptr: u32, _t: &mut ThreadState) -> Result<()> {
    if ptr == 0 {
        return Ok(());
    }
    mem.write_bytes(ptr, &[0u8; 48])?;
    mem.write_u32(ptr, 1280)?;
    mem.write_u32(ptr + 4, 720)?;
    mem.write_u32(ptr + 8, 0)?; // interlaced
    mem.write_u32(ptr + 12, 1)?; // widescreen
    mem.write_u32(ptr + 16, 1)?; // hi-def
    mem.write_bytes(ptr + 20, &60.0f32.to_be_bytes())?;
    mem.write_u32(ptr + 24, 1)?; // NTSCM
    mem.write_u32(ptr + 28, 0x8A)?; // pixel_rate
    mem.write_u32(ptr + 32, 0x01)?; // widescreen_flag
    Ok(())
}

/// `NetDll_WSAStartup(version, data_ptr)`: X_WSADATA is 0x190 bytes
/// (version/version_high u16be, 257+129 description bytes, two u16,
/// vendor pointer). Mirrors the reference non-Windows path.
fn netdll_wsa_startup(
    mem: &mut Memory,
    version: u32,
    data_ptr: u32,
    t: &mut ThreadState,
) -> Result<()> {
    if data_ptr != 0 {
        mem.write_bytes(data_ptr, &vec![0u8; 0x190])?;
        write_u16be(mem, data_ptr, (version & 0xFFFF) as u16)?;
        write_u16be(mem, data_ptr + 2, 0x0202)?;
    }
    t.gpr[3] = 0_u64;
    Ok(())
}

/// `XNotifyGetNext(handle, match, id_ptr, param_ptr)` (reference
/// `am_notify.cc`): param/id words are zeroed first; a null id
/// pointer returns 0; unknown handles return 0; otherwise 1 when an
/// entry was dequeued, else 0.
fn xnotify_get_next(
    kernel: &mut Kernel,
    mem: &mut Memory,
    handle: u32,
    match_id: u32,
    id_ptr: u32,
    param_ptr: u32,
    t: &mut ThreadState,
) -> Result<()> {
    if param_ptr != 0 {
        mem.write_u32(param_ptr, 0)?;
    }
    if id_ptr == 0 {
        t.gpr[3] = 0_u64;
        return Ok(());
    }
    mem.write_u32(id_ptr, 0)?;
    let Some((dequeued, id, param)) = kernel.notify_get_next(handle, match_id) else {
        t.gpr[3] = 0_u64;
        return Ok(());
    };
    if dequeued {
        mem.write_u32(id_ptr, id)?;
        if param_ptr != 0 {
            mem.write_u32(param_ptr, param)?;
        }
        t.gpr[3] = 1_u64;
    } else {
        t.gpr[3] = 0_u64;
    }
    Ok(())
}

/// `RtlNtStatusToDosError(status)` (reference
/// `xboxkrnl_error.cc` `xeRtlNtStatusToDosError`): NTSTATUS to Win32
/// error. Structural rules are exact (identity for 0 / 0x20000000-bit,
/// low-word for 0x8007xx / 0xC001xx, 317 fallback). The table below
/// covers every status this kernel emits (entries verified against
/// `error_table_0x00000103` / `error_table_0xC0000001`); anything else
/// returns 317 (ERROR_MR_MID_NOT_FOUND) exactly like the reference
/// does for unmapped codes. Extend the table (from the reference)
/// when retail surfaces a new status instead of guessing.
fn rtl_nt_status_to_dos_error(status: u32, t: &mut ThreadState) -> Result<()> {
    t.gpr[3] = (nt_status_to_dos_error(status)) as u64;
    Ok(())
}

fn nt_status_to_dos_error(status: u32) -> u32 {
    if status == 0 || (status & 0x2000_0000) != 0 {
        return status;
    }
    if (status >> 16) == 0x8007 {
        return status & 0xFFFF;
    }
    let mut s = status;
    if (s & 0xF000_0000) == 0xD000_0000 {
        s &= !0x3000_0000;
    }
    // (base, entries): verified against the reference tables.
    const T103: &[u32] = &[997];
    const TC0000001: &[u32] = &[
        31,
        1,
        87,
        24,
        0x3E6,
        0x3E7,
        0x5AE,
        6,
        0x3E9,
        0xC1,
        87,
        0,
        87,
        2,
        2,
        1,
        38,
        0x22,
        0x15,
        0x6F9,
        0x1B,
        0xEA,
        8,
        0x1E7,
        0x1E7,
        87,
        87,
        1,
        0xC000_001D,
        5,
        5,
        0xC1,
        5,
        5,
        122,
        6,
        0xC000_0025,
        0xC000_0026,
        0,
        0,
        0,
        0x9E,
        0xC000_002B,
        0x1E7,
        0x1E7,
        0,
        0,
        87,
        0,
        0x571,
        123,
        2,
        183,
        0,
        6,
        0,
        0xA1,
        3,
    ];
    for (base, table) in [(0x0000_0103u32, T103), (0xC000_0001u32, TC0000001)] {
        if s < base {
            break;
        }
        let idx = (s - base) as usize;
        if idx < table.len() {
            let r = table[idx];
            if r != 0 {
                return r;
            }
            break;
        }
    }
    // Late table entries this kernel emits (verified individually).
    match s {
        0xC000_00BA => 5,   // FILE_IS_A_DIRECTORY -> ACCESS_DENIED
        0xC000_00F1 => 87,  // INVALID_PARAMETER_3 -> INVALID_PARAMETER
        0xC000_0103 => 267, // NOT_A_DIRECTORY -> ERROR_DIRECTORY
        _ => {
            if (s >> 16) == 0xC001 {
                return s & 0xFFFF;
            }
            317 // ERROR_MR_MID_NOT_FOUND, like the reference.
        }
    }
}
/// `XMsgInProcessCall(app, message, _, _)` message table for the
/// LiveBase app (0xFC). Values verified against reference
/// `apps/xlivebase_app.cc` (`XLiveBaseLogonGetHR` and siblings);
/// the offline answers (disconnected / not-logged-on) are the
/// genuine no-network results, matching a box with no Live sign-in.
fn xmsg_in_process_call(app: u32, message: u32, t: &mut ThreadState) -> Result<()> {
    const X_E_FAIL: u32 = 0x8000_4005;
    const X_E_NOTFOUND: u32 = 0x8007_0002;
    let r = match app {
        0xFC => match message {
            0x0005_008C | 0x0005_0094 | 0x0005_8020 | 0x0005_8023 => X_E_FAIL,
            0x0005_8003 => 0x0015_10F1, // X_ONLINE_S_LOGON_DISCONNECTED
            0x0005_8004 | 0x0005_8037 | 0x0005_8046 => 0, // X_E_SUCCESS
            0x0005_8006 | 0x0005_8007 => 0x8015_1802, // NOT_LOGGED_ON
            _ => X_E_FAIL,
        },
        _ => X_E_NOTFOUND,
    };
    t.gpr[3] = (r) as u64;
    Ok(())
}

/// Guest `X_ERWLOCK` (reference `xboxkrnl_threading.cc`, 0x38 bytes):
/// lock_count i32 @+0, writers_waiting @+4, readers_waiting @+8,
/// readers_entry @+12, writer event (16B) @+16, reader semaphore
/// (20B) @+32, spin lock @+52. The semaphore limit sits @+48 and the
/// event/semaphore signal states @+20/@+36.
fn erw_init(mem: &mut Memory, lock: u32) -> Result<()> {
    mem.write_u32(lock, 0xFFFF_FFFF)?; // lock_count = -1
    mem.write_u32(lock + 4, 0)?;
    mem.write_u32(lock + 8, 0)?;
    mem.write_u32(lock + 12, 0)?;
    // KeInitializeEvent(&writer_event, type=1 sync, initial=0):
    // zero the 16-byte event, then type + signal_state.
    mem.write_bytes(lock + 16, &[0u8; 16])?;
    mem.write_u8(lock + 16, 1)?; // EventSynchronizationObject
    mem.write_u32(lock + 20, 0)?;
    // KeInitializeSemaphore(&reader_semaphore, 0, 0x7FFFFFFF).
    mem.write_u8(lock + 32, 5)?; // SemaphoreObject
    mem.write_u32(lock + 36, 0)?;
    mem.write_u32(lock + 48, 0x7FFF_FFFF)?;
    mem.write_u32(lock + 52, 0)?; // spin_lock owner
    Ok(())
}

/// Blocking acquire. Uncontended fast paths match the reference
/// exactly; contended (would-block) states record the reference's
/// counter updates, then report Unsupported explicitly.
fn erw_acquire(mem: &mut Memory, lock: u32, exclusive: bool) -> Result<()> {
    let lc = mem.read_u32(lock)? as i32 + 1;
    mem.write_u32(lock, lc as u32)?;
    if exclusive {
        if lc == 0 {
            return Ok(());
        }
        mem.write_u32(lock + 4, mem.read_u32(lock + 4)? + 1)?;
        return Err(EmuError::Unsupported(format!(
            "contended ExAcquireReadWriteLockExclusive {:08x} would block",
            lock
        )));
    }
    let entry = mem.read_u32(lock + 12)?;
    let waiting = mem.read_u32(lock + 4)?;
    if lc == 0 || (entry != 0 && waiting == 0) {
        mem.write_u32(lock + 12, entry + 1)?;
        return Ok(());
    }
    mem.write_u32(lock + 8, mem.read_u32(lock + 8)? + 1)?;
    Err(EmuError::Unsupported(format!(
        "contended ExAcquireReadWriteLockShared {:08x} would block",
        lock
    )))
}

/// Try-acquire. Never blocks; 1 = acquired, 0 = busy.
fn erw_try(mem: &mut Memory, lock: u32, exclusive: bool, t: &mut ThreadState) -> Result<()> {
    let lc = mem.read_u32(lock)? as i32;
    let r = if exclusive {
        if lc < 0 {
            mem.write_u32(lock, 0)?;
            1
        } else {
            0
        }
    } else {
        let entry = mem.read_u32(lock + 12)?;
        let waiting = mem.read_u32(lock + 4)?;
        if lc < 0 || (entry != 0 && waiting == 0) {
            mem.write_u32(lock, (lc + 1) as u32)?;
            mem.write_u32(lock + 12, entry + 1)?;
            1
        } else {
            0
        }
    };
    t.gpr[3] = (r) as u64;
    Ok(())
}

/// Release (reference `ExReleaseReadWriteLock_entry`), including the
/// waiter-wakeup counter moves and signal-state updates.
fn erw_release(mem: &mut Memory, lock: u32) -> Result<()> {
    let lc = mem.read_u32(lock)? as i32 - 1;
    mem.write_u32(lock, lc as u32)?;
    if lc < 0 {
        mem.write_u32(lock + 12, 0)?;
        return Ok(());
    }
    if mem.read_u32(lock + 12)? == 0 {
        let waiting = mem.read_u32(lock + 8)?;
        if waiting != 0 {
            mem.write_u32(lock + 8, 0)?;
            mem.write_u32(lock + 12, waiting)?;
            let sig = mem.read_u32(lock + 36)?;
            mem.write_u32(lock + 36, sig + waiting)?;
            return Ok(());
        }
    }
    let entry = mem.read_u32(lock + 12)? - 1;
    mem.write_u32(lock + 12, entry)?;
    if entry != 0 {
        return Ok(());
    }
    mem.write_u32(lock + 4, mem.read_u32(lock + 4)? - 1)?;
    mem.write_u32(lock + 20, 1)?; // wake one writer
    Ok(())
}

/// `RtlGetStackLimits(low_ptr, high_ptr)`: report the recorded stack.
fn rtl_get_stack_limits(
    kernel: &Kernel,
    mem: &mut Memory,
    low_ptr: u32,
    high_ptr: u32,
    t: &mut ThreadState,
) -> Result<()> {
    if low_ptr == 0 || high_ptr == 0 {
        return Err(EmuError::Other("null stack-limit pointer".into()));
    }
    mem.write_u32(low_ptr, kernel.stack_base())?;
    mem.write_u32(
        high_ptr,
        kernel.stack_base().wrapping_add(kernel.stack_size()),
    )?;
    t.gpr[3] = 0_u64;
    Ok(())
}

fn rtl_xex_header_field(
    kernel: &Kernel,
    header_ptr: u32,
    field: u32,
    t: &mut ThreadState,
) -> Result<()> {
    if header_ptr == 0 {
        t.gpr[3] = 0_u64;
        return Ok(());
    }
    // Serve from the stored header image when it covers the request,
    // else from module facts for the handful of inline keys games poll.
    if let Some(v) = kernel.xex_header_field(header_ptr, field) {
        t.gpr[3] = (v) as u64;
        return Ok(());
    }
    t.gpr[3] = (match field {
        0x0001_0100 => kernel.entry_point(),
        0x0001_0201 => kernel.image_base,
        0x0004_0006 => kernel.title_id, // execution-info title id (caller reads +0xC)
        _ => 0,
    }) as u64;
    Ok(())
}

/// `XexCheckExecutablePrivilege(privilege)`: test one system-flag bit
/// (reference `xboxkrnl_modules.cc`; privilege is a bit position into
/// the `XEX_HEADER_SYSTEM_FLAGS` word). Returns 1/0, never traps.
fn xex_check_privilege(kernel: &Kernel, privilege: u32, t: &mut ThreadState) -> Result<()> {
    if privilege >= 32 {
        t.gpr[3] = 0_u64;
        return Ok(());
    }
    let mask = 1u32 << privilege;
    t.gpr[3] = (u32::from(kernel.system_flags & mask != 0)) as u64;
    Ok(())
}

fn xex_get_module_handle(
    kernel: &Kernel,
    mem: &mut Memory,
    name_ptr: u32,
    out_ptr: u32,
    t: &mut ThreadState,
) -> Result<()> {
    if out_ptr == 0 {
        t.gpr[3] = (STATUS_INVALID_PARAMETER) as u64;
        return Ok(());
    }
    if name_ptr == 0 {
        // Current executable: the image base serves as the handle.
        mem.write_u32(out_ptr, kernel.image_base)?;
        t.gpr[3] = (ERROR_SUCCESS) as u64;
        return Ok(());
    }
    let name = read_cstr(mem, name_ptr).unwrap_or_default();
    let want = String::from_utf8_lossy(&name).to_ascii_lowercase();
    // Opaque pseudo-handles for the two linked system modules; the
    // only valid use sites (GetModuleSection/GetProcedureAddress)
    // validate them explicitly.
    const XAM_HANDLE: u32 = 0x9000_0001;
    const XRNL_HANDLE: u32 = 0x9000_0002;
    if want == "xam.xex" {
        mem.write_u32(out_ptr, XAM_HANDLE)?;
        t.gpr[3] = (ERROR_SUCCESS) as u64;
    } else if want == "xboxkrnl.exe" {
        mem.write_u32(out_ptr, XRNL_HANDLE)?;
        t.gpr[3] = (ERROR_SUCCESS) as u64;
    } else {
        mem.write_u32(out_ptr, 0)?;
        t.gpr[3] = (ERROR_NOT_FOUND) as u64;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::imports::ImportTable;
    use crate::Kernel;

    fn thread() -> ThreadState {
        ThreadState::new(0, 0x8200_1000)
    }

    fn imp(lib: &str, ord: u16) -> ResolvedImport {
        ResolvedImport {
            lib: lib.into(),
            ordinal: ord,
            kind: crate::imports::ImportKind::Function,
            thunk_addr: 0x8200_2000,
        }
    }

    #[test]
    fn vd_initialize_engines_records() {
        // Hex sanity: dispatch arms must match the authoritative table.
        assert_eq!(
            ImportTable::name_of("xboxkrnl.exe", 0x1D5),
            Some("VdSetGraphicsInterruptCallback")
        );
        assert_eq!(
            ImportTable::name_of("xboxkrnl.exe", 0x1C3),
            Some("VdInitializeRingBuffer")
        );
        assert_eq!(
            ImportTable::name_of("xboxkrnl.exe", 0x1B6),
            Some("VdEnableRingBufferRPtrWriteBack")
        );
        assert_eq!(
            ImportTable::name_of("xboxkrnl.exe", 0x1BD),
            Some("VdGetSystemCommandBuffer")
        );
        assert_eq!(
            ImportTable::name_of("xboxkrnl.exe", 0x1BC),
            Some("VdGetGraphicsAsicID")
        );
        assert_eq!(
            ImportTable::name_of("xboxkrnl.exe", 0x1C6),
            Some("VdIsHSIOTrainingSucceeded")
        );
        assert_eq!(
            ImportTable::name_of("xboxkrnl.exe", 0x1C7),
            Some("VdPersistDisplay")
        );
        assert_eq!(
            ImportTable::name_of("xboxkrnl.exe", 0x1DC),
            Some("VdShutdownEngines")
        );
        assert_eq!(
            ImportTable::name_of("xboxkrnl.exe", 0x1D3),
            Some("VdSetDisplayMode")
        );
        let mut k = Kernel::new();
        let mut m = Memory::new();
        let mut tab = ImportTable::new();
        let mut t = thread();
        t.gpr[3] = 0x1B53_0000;
        t.gpr[4] = 0x8218_4060;
        t.gpr[5] = 0;
        t.gpr[6] = 0x8200_5818;
        t.gpr[7] = 0x8200_5C98;
        dispatch_import(
            &mut k,
            &mut m,
            &mut tab,
            0,
            &mut t,
            &imp("xboxkrnl.exe", 0x1C2),
        )
        .unwrap();
        assert_eq!(t.gpr[3] as u32, 1);
        let vd = k.vd_engines.expect("recorded");
        assert_eq!(vd.callback, 0x8218_4060);
        assert_eq!(vd.pfp_ptr, 0x8200_5818);
        assert_eq!(vd.me_ptr, 0x8200_5C98);
        // Interrupt callback + ring records.
        t.gpr[3] = 0x8218_1718;
        t.gpr[4] = 0x0104_3800;
        dispatch_import(
            &mut k,
            &mut m,
            &mut tab,
            0,
            &mut t,
            &imp("xboxkrnl.exe", 0x1D5),
        )
        .unwrap();
        assert_eq!(k.vd_interrupt, Some((0x8218_1718, 0x0104_3800)));
        t.gpr[3] = 0x0110_0000;
        t.gpr[4] = 20;
        // Dirty the range first so the test proves the zeroing.
        m.write_u32(0x0110_0000, 0xDEAD_BEEF).unwrap();
        m.write_u32(0x0110_0000 + (1 << 23) - 4, 0xDEAD_BEEF)
            .unwrap();
        dispatch_import(
            &mut k,
            &mut m,
            &mut tab,
            0,
            &mut t,
            &imp("xboxkrnl.exe", 0x1C3),
        )
        .unwrap();
        assert_eq!(k.vd_ring, Some((0x0110_0000, 20)));
        // Ring buffer is zeroed: 1 << (20 + 3) bytes at the pointer.
        assert_eq!(m.read_u32(0x0110_0000).unwrap(), 0);
        assert_eq!(m.read_u32(0x0110_0000 + (1 << 23) - 4).unwrap(), 0);
        // Out-of-DRAM ring is an explicit error, never silent.
        t.gpr[3] = 0x796F_7518;
        t.gpr[4] = 20;
        assert!(dispatch_import(
            &mut k,
            &mut m,
            &mut tab,
            0,
            &mut t,
            &imp("xboxkrnl.exe", 0x1C3),
        )
        .is_err());
        // System command buffer magics.
        let p0 = 0x8400_C000;
        let p1 = 0x8400_C100;
        t.gpr[3] = p0 as u64;
        t.gpr[4] = p1 as u64;
        dispatch_import(
            &mut k,
            &mut m,
            &mut tab,
            0,
            &mut t,
            &imp("xboxkrnl.exe", 0x1BD),
        )
        .unwrap();
        assert_eq!(m.read_u32(p0).unwrap(), 0xBEEF_0000);
        assert_eq!(m.read_u32(p0 + 4).unwrap(), 0);
        assert_eq!(m.read_u32(p1).unwrap(), 0xBEEF_0001);
        // Asic ID steers clear of the EDRAM-retrain path.
        dispatch_import(
            &mut k,
            &mut m,
            &mut tab,
            0,
            &mut t,
            &imp("xboxkrnl.exe", 0x1BC),
        )
        .unwrap();
        assert_eq!(t.gpr[3] as u32, 0x11);
        // Video mode struct + flags.
        let vm = 0x8400_C200;
        t.gpr[3] = vm as u64;
        dispatch_import(
            &mut k,
            &mut m,
            &mut tab,
            0,
            &mut t,
            &imp("xboxkrnl.exe", 0x1CA),
        )
        .unwrap();
        assert_eq!(m.read_u32(vm).unwrap(), 1280);
        assert_eq!(m.read_u32(vm + 4).unwrap(), 720);
        assert_eq!(m.read_u32(vm + 12).unwrap(), 1);
        assert_eq!(m.read_u32(vm + 16).unwrap(), 1);
        assert_eq!(m.read_u32(vm + 24).unwrap(), 1);
        assert_eq!(m.read_u32(vm + 28).unwrap(), 0x8A);
        dispatch_import(
            &mut k,
            &mut m,
            &mut tab,
            0,
            &mut t,
            &imp("xboxkrnl.exe", 0x1C9),
        )
        .unwrap();
        assert_eq!(t.gpr[3] as u32, 3);
        // Graphics notification call is a 0-return like the reference.
        assert_eq!(
            ImportTable::name_of("xboxkrnl.exe", 0x1B1),
            Some("VdCallGraphicsNotificationRoutines")
        );
        t.gpr[3] = 1;
        t.gpr[4] = 0x8400_C300;
        dispatch_import(
            &mut k,
            &mut m,
            &mut tab,
            0,
            &mut t,
            &imp("xboxkrnl.exe", 0x1B1),
        )
        .unwrap();
        assert_eq!(t.gpr[3] as u32, 0);
        // Display gamma defaults: TV + power.
        assert_eq!(
            ImportTable::name_of("xboxkrnl.exe", 0x1B9),
            Some("VdGetCurrentDisplayGamma")
        );
        let gt = 0x8400_C400;
        let gp = 0x8400_C404;
        t.gpr[3] = gt as u64;
        t.gpr[4] = gp as u64;
        dispatch_import(
            &mut k,
            &mut m,
            &mut tab,
            0,
            &mut t,
            &imp("xboxkrnl.exe", 0x1B9),
        )
        .unwrap();
        assert_eq!(m.read_u32(gt).unwrap(), 2);
        let b = m.read_bytes(gp, 4).unwrap();
        assert_eq!(
            f32::from_be_bytes([b[0], b[1], b[2], b[3]]),
            2.22222233_f64 as f32
        );
    }

    #[test]
    fn terminate_notification_register_remove() {
        let mut k = Kernel::new();
        let mut m = Memory::new();
        let mut tab = ImportTable::new();
        let mut t = thread();
        let reg = 0x8400_B000;
        m.write_u32(reg, 0x8256_09C0).unwrap();
        m.write_u32(reg + 4, 1).unwrap();
        t.gpr[3] = reg as u64;
        t.gpr[4] = 1;
        dispatch_import(
            &mut k,
            &mut m,
            &mut tab,
            0,
            &mut t,
            &imp("xboxkrnl.exe", 0x15),
        )
        .unwrap();
        assert_eq!(k.terminate_notifications.len(), 1);
        assert_eq!(k.terminate_notifications[0].routine, 0x8256_09C0);
        t.gpr[3] = reg as u64;
        t.gpr[4] = 0;
        dispatch_import(
            &mut k,
            &mut m,
            &mut tab,
            0,
            &mut t,
            &imp("xboxkrnl.exe", 0x15),
        )
        .unwrap();
        assert!(k.terminate_notifications.is_empty());
    }

    #[test]
    fn xconfig_serves_language() {
        let mut k = Kernel::new();
        let mut m = Memory::new();
        let mut tab = ImportTable::new();
        let mut t = thread();
        // ExGetXConfigSetting(USER, LANGUAGE, buf, 4, req).
        let buf: u32 = 0x8400_8000;
        let req: u32 = 0x8400_8004;
        t.gpr[3] = 3;
        t.gpr[4] = 0x09;
        t.gpr[5] = buf as u64;
        t.gpr[6] = 4;
        t.gpr[7] = req as u64;
        dispatch_import(
            &mut k,
            &mut m,
            &mut tab,
            0,
            &mut t,
            &imp("xboxkrnl.exe", 0x10),
        )
        .unwrap();
        assert_eq!(t.gpr[3] as u32, STATUS_SUCCESS);
        assert_eq!(m.read_u32(buf).unwrap(), 1);
        assert_eq!(read_u16be(&m, req).unwrap(), 4);
        // Too-small buffer is BUFFER_TOO_SMALL, buffer untouched.
        m.write_u32(buf, 0xDEAD_BEEF).unwrap();
        t.gpr[3] = 3;
        t.gpr[4] = 0x09;
        t.gpr[5] = buf as u64;
        t.gpr[6] = 2;
        t.gpr[7] = req as u64;
        dispatch_import(
            &mut k,
            &mut m,
            &mut tab,
            0,
            &mut t,
            &imp("xboxkrnl.exe", 0x10),
        )
        .unwrap();
        assert_eq!(t.gpr[3] as u32, STATUS_BUFFER_TOO_SMALL);
        assert_eq!(m.read_u32(buf).unwrap(), 0xDEAD_BEEF);
        // Unknown setting: SUCCESS, required 0, buffer untouched.
        t.gpr[3] = 3;
        t.gpr[4] = 0x7F;
        t.gpr[5] = buf as u64;
        t.gpr[6] = 4;
        t.gpr[7] = req as u64;
        dispatch_import(
            &mut k,
            &mut m,
            &mut tab,
            0,
            &mut t,
            &imp("xboxkrnl.exe", 0x10),
        )
        .unwrap();
        assert_eq!(t.gpr[3] as u32, STATUS_SUCCESS);
        assert_eq!(read_u16be(&m, req).unwrap(), 0);
        // Null buffer with nonzero size is INVALID_PARAMETER_3.
        t.gpr[3] = 3;
        t.gpr[4] = 0x09;
        t.gpr[5] = 0;
        t.gpr[6] = 4;
        t.gpr[7] = 0;
        dispatch_import(
            &mut k,
            &mut m,
            &mut tab,
            0,
            &mut t,
            &imp("xboxkrnl.exe", 0x10),
        )
        .unwrap();
        assert_eq!(t.gpr[3] as u32, STATUS_INVALID_PARAMETER_3);
    }

    #[test]
    fn ke_thread_ptr_apis() {
        let mut k = Kernel::new();
        let mut m = Memory::new();
        let mut tab = ImportTable::new();
        let mut t = thread();
        // Create a thread to get a KTHREAD pointer.
        let hp: u32 = 0x8400_7000;
        let ip: u32 = 0x8400_7004;
        t.gpr[3] = hp as u64;
        t.gpr[4] = 0x4000;
        t.gpr[5] = ip as u64;
        t.gpr[6] = 0;
        t.gpr[7] = 0x8250_2000;
        t.gpr[8] = 0;
        t.gpr[9] = 0;
        dispatch_import(
            &mut k,
            &mut m,
            &mut tab,
            7,
            &mut t,
            &imp("xboxkrnl.exe", 0x0D),
        )
        .unwrap();
        assert_eq!(t.gpr[3] as u32, STATUS_SUCCESS);
        let h = m.read_u32(hp).unwrap();
        let kp = k.nt_threads.get(&h).copied().expect("tracked").kthread_ptr;
        // Affinity: set 0x20, prev was 1 (cpu 0).
        let pp: u32 = 0x8400_7010;
        t.gpr[3] = kp as u64;
        t.gpr[4] = 0x20;
        t.gpr[5] = pp as u64;
        dispatch_import(
            &mut k,
            &mut m,
            &mut tab,
            7,
            &mut t,
            &imp("xboxkrnl.exe", 0x97),
        )
        .unwrap();
        assert_eq!(t.gpr[3] as u32, STATUS_SUCCESS);
        assert_eq!(m.read_u32(pp).unwrap(), 1);
        assert_eq!(k.nt_threads.get(&h).copied().expect("t").active_cpu, 5);
        // Zero affinity is INVALID_PARAMETER.
        t.gpr[3] = kp as u64;
        t.gpr[4] = 0;
        t.gpr[5] = 0;
        dispatch_import(
            &mut k,
            &mut m,
            &mut tab,
            7,
            &mut t,
            &imp("xboxkrnl.exe", 0x97),
        )
        .unwrap();
        assert_eq!(t.gpr[3] as u32, STATUS_INVALID_PARAMETER);
        // Priority query/set roundtrip.
        t.gpr[3] = kp as u64;
        dispatch_import(
            &mut k,
            &mut m,
            &mut tab,
            7,
            &mut t,
            &imp("xboxkrnl.exe", 0x81),
        )
        .unwrap();
        assert_eq!(t.gpr[3] as u32, 8);
        t.gpr[3] = kp as u64;
        t.gpr[4] = 12;
        dispatch_import(
            &mut k,
            &mut m,
            &mut tab,
            7,
            &mut t,
            &imp("xboxkrnl.exe", 0x99),
        )
        .unwrap();
        assert_eq!(t.gpr[3] as u32, 8);
        assert_eq!(m.read_u8(kp + 0x70).unwrap(), 12);
        // Boost exchange.
        t.gpr[3] = kp as u64;
        t.gpr[4] = 1;
        dispatch_import(
            &mut k,
            &mut m,
            &mut tab,
            7,
            &mut t,
            &imp("xboxkrnl.exe", 0x9C),
        )
        .unwrap();
        assert_eq!(t.gpr[3] as u32, 0);
        // Unknown pointer fails genuinely.
        t.gpr[3] = 0x1234_5000;
        t.gpr[4] = 0x20;
        t.gpr[5] = 0;
        dispatch_import(
            &mut k,
            &mut m,
            &mut tab,
            7,
            &mut t,
            &imp("xboxkrnl.exe", 0x97),
        )
        .unwrap();
        assert_eq!(t.gpr[3] as u32, STATUS_INVALID_HANDLE);
    }

    #[test]
    fn ob_reference_and_lookup() {
        let mut k = Kernel::new();
        let mut m = Memory::new();
        let mut tab = ImportTable::new();
        let mut t = thread();
        // Create a semaphore, then resolve its handle to a guest ptr.
        let hp = 0x8400_6000;
        t.gpr[3] = hp as u64;
        t.gpr[4] = 0;
        t.gpr[5] = 2;
        t.gpr[6] = 4;
        dispatch_import(
            &mut k,
            &mut m,
            &mut tab,
            7,
            &mut t,
            &imp("xboxkrnl.exe", 0xD5),
        )
        .unwrap();
        assert_eq!(t.gpr[3] as u32, STATUS_SUCCESS);
        let h = m.read_u32(hp).unwrap();
        let op = 0x8400_6010;
        t.gpr[3] = h as u64;
        t.gpr[4] = 0;
        t.gpr[5] = op as u64;
        dispatch_import(
            &mut k,
            &mut m,
            &mut tab,
            7,
            &mut t,
            &imp("xboxkrnl.exe", 0x110),
        )
        .unwrap();
        assert_eq!(t.gpr[3] as u32, STATUS_SUCCESS);
        let native = m.read_u32(op).unwrap();
        assert_ne!(native, 0);
        // Guest struct carries the semaphore facts (header type 5,
        // count 2, limit 4).
        assert_eq!(m.read_u8(native).unwrap(), 5);
        assert_eq!(m.read_u32(native + 4).unwrap(), 2);
        assert_eq!(m.read_u32(native + 0x10).unwrap(), 4);
        // Bad handle zeroes out and reports INVALID_HANDLE.
        t.gpr[3] = 0xDEAD_BEEF;
        t.gpr[4] = 0;
        t.gpr[5] = op as u64;
        dispatch_import(
            &mut k,
            &mut m,
            &mut tab,
            7,
            &mut t,
            &imp("xboxkrnl.exe", 0x110),
        )
        .unwrap();
        assert_eq!(t.gpr[3] as u32, STATUS_INVALID_HANDLE);
        assert_eq!(m.read_u32(op).unwrap(), 0);
        // Thread lookup by id.
        let thp: u32 = 0x8400_6020;
        let tip: u32 = 0x8400_6024;
        t.gpr[3] = thp as u64;
        t.gpr[4] = 0x4000;
        t.gpr[5] = tip as u64;
        t.gpr[6] = 0;
        t.gpr[7] = 0x8250_1000;
        t.gpr[8] = 0;
        t.gpr[9] = 0;
        dispatch_import(
            &mut k,
            &mut m,
            &mut tab,
            7,
            &mut t,
            &imp("xboxkrnl.exe", 0x0D),
        )
        .unwrap();
        assert_eq!(t.gpr[3] as u32, STATUS_SUCCESS);
        let tid = m.read_u32(tip).unwrap();
        let lop = 0x8400_6030;
        t.gpr[3] = tid as u64;
        t.gpr[4] = lop as u64;
        dispatch_import(
            &mut k,
            &mut m,
            &mut tab,
            7,
            &mut t,
            &imp("xboxkrnl.exe", 0x10B),
        )
        .unwrap();
        assert_eq!(t.gpr[3] as u32, STATUS_SUCCESS);
        assert_ne!(m.read_u32(lop).unwrap(), 0);
        // Unknown thread id fails genuinely.
        t.gpr[3] = 0xFFFF_FFFE;
        t.gpr[4] = lop as u64;
        dispatch_import(
            &mut k,
            &mut m,
            &mut tab,
            7,
            &mut t,
            &imp("xboxkrnl.exe", 0x10B),
        )
        .unwrap();
        assert_eq!(t.gpr[3] as u32, STATUS_INVALID_HANDLE);
    }

    #[test]
    fn nt_thread_create_resume() {
        let mut k = Kernel::new();
        let mut m = Memory::new();
        let mut tab = ImportTable::new();
        let mut t = thread();
        // ExCreateThread(handle_ptr, stack=0x10000, id_ptr, startup=0,
        // start, ctx, flags=suspended).
        let hp = 0x8400_5000;
        let ip = 0x8400_5004;
        t.gpr[3] = hp as u64;
        t.gpr[4] = 0x1_0000;
        t.gpr[5] = ip as u64;
        t.gpr[6] = 0;
        t.gpr[7] = 0x8250_0000;
        t.gpr[8] = 0x1234;
        t.gpr[9] = 0x1;
        dispatch_import(
            &mut k,
            &mut m,
            &mut tab,
            7,
            &mut t,
            &imp("xboxkrnl.exe", 0x0D),
        )
        .unwrap();
        assert_eq!(t.gpr[3] as u32, STATUS_SUCCESS);
        let h = m.read_u32(hp).unwrap();
        assert_ne!(h, 0);
        assert_ne!(m.read_u32(ip).unwrap(), 0);
        let th = k.nt_threads.get(&h).copied().expect("tracked");
        assert_eq!(th.suspend_count, 1);
        assert_eq!(th.start_addr, 0x8250_0000);
        // Stack is real zeroed bytes.
        assert_eq!(&m.read_bytes(th.stack_base, 4).unwrap(), &[0, 0, 0, 0]);
        // KTHREAD carries the stack range.
        assert_eq!(m.read_u32(th.kthread_ptr + 0x60).unwrap(), th.stack_base);
        // Resume reports prev 1 then 0.
        let pp = 0x8400_5010;
        t.gpr[3] = h as u64;
        t.gpr[4] = pp as u64;
        dispatch_import(
            &mut k,
            &mut m,
            &mut tab,
            7,
            &mut t,
            &imp("xboxkrnl.exe", 0xF5),
        )
        .unwrap();
        assert_eq!(t.gpr[3] as u32, STATUS_SUCCESS);
        assert_eq!(m.read_u32(pp).unwrap(), 1);
        t.gpr[3] = h as u64;
        t.gpr[4] = pp as u64;
        dispatch_import(
            &mut k,
            &mut m,
            &mut tab,
            7,
            &mut t,
            &imp("xboxkrnl.exe", 0xF5),
        )
        .unwrap();
        assert_eq!(m.read_u32(pp).unwrap(), 0);
        // Null start address is INVALID_PARAMETER with zero handle.
        t.gpr[3] = hp as u64;
        t.gpr[4] = 0x1000;
        t.gpr[5] = ip as u64;
        t.gpr[6] = 0;
        t.gpr[7] = 0;
        t.gpr[8] = 0;
        t.gpr[9] = 0;
        dispatch_import(
            &mut k,
            &mut m,
            &mut tab,
            7,
            &mut t,
            &imp("xboxkrnl.exe", 0x0D),
        )
        .unwrap();
        assert_eq!(t.gpr[3] as u32, STATUS_INVALID_PARAMETER);
        assert_eq!(m.read_u32(hp).unwrap(), 0);
        // Bad resume handle is INVALID_HANDLE.
        t.gpr[3] = 0xDEAD_BEEF;
        t.gpr[4] = 0;
        dispatch_import(
            &mut k,
            &mut m,
            &mut tab,
            7,
            &mut t,
            &imp("xboxkrnl.exe", 0xF5),
        )
        .unwrap();
        assert_eq!(t.gpr[3] as u32, STATUS_INVALID_HANDLE);
    }

    #[test]
    fn nt_file_open_read_close() {
        use crate::fs::{FsLookup, GuestFs};
        use std::collections::HashMap;
        use std::sync::Arc;
        struct MockFs {
            files: HashMap<String, Vec<u8>>,
        }
        impl GuestFs for MockFs {
            fn lookup(&self, path: &str) -> FsLookup {
                if let Some(b) = self.files.get(path) {
                    return FsLookup::File(Arc::from(b.as_slice()));
                }
                FsLookup::NotFound
            }
        }
        #[allow(clippy::too_many_arguments)]
        fn open_path(
            k: &mut Kernel,
            m: &mut Memory,
            tab: &mut ImportTable,
            t: &mut ThreadState,
            raw: &[u8],
            access: u32,
            disposition: u32,
            options: u32,
        ) -> (u32, u32, u32) {
            // OA + ANSI + bytes laid out in guest memory.
            let oa = 0x8400_A000;
            let an = 0x8400_A010;
            let sb = 0x8400_A020;
            let ho = 0x8400_A100;
            let io = 0x8400_A108;
            m.write_bytes(sb, raw).unwrap();
            m.write_u32(oa, 0xFFFF_FFFD).unwrap();
            m.write_u32(oa + 4, an).unwrap();
            m.write_u32(oa + 8, 0x40).unwrap();
            let lb = (raw.len() as u16).to_be_bytes();
            m.write_bytes(an, &[lb[0], lb[1], lb[0], lb[1]]).unwrap();
            m.write_u32(an + 4, sb).unwrap();
            t.gpr[3] = ho as u64;
            t.gpr[4] = access as u64;
            t.gpr[5] = oa as u64;
            t.gpr[6] = io as u64;
            t.gpr[7] = 0;
            t.gpr[8] = 0x80;
            t.gpr[9] = 1;
            t.gpr[10] = disposition as u64;
            // options is the 9th arg: spill to the guest stack.
            let r1 = 0x8400_B000;
            t.gpr[1] = r1 as u64;
            m.write_bytes(r1, &[0u8; 64]).unwrap();
            m.write_u32(r1 + 8, options).unwrap();
            dispatch_import(k, m, tab, 7, t, &imp("xboxkrnl.exe", 0xD2)).unwrap();
            (
                t.gpr[3] as u32,
                m.read_u32(ho).unwrap(),
                m.read_u32(io + 4).unwrap(),
            )
        }
        let mut k = Kernel::new();
        let mut m = Memory::new();
        let mut tab = ImportTable::new();
        let mut t = thread();
        k.set_fs(Arc::new(MockFs {
            files: [("data/strings/english.mo".to_string(), vec![9, 8, 7, 6, 5])].into(),
        }));
        // Open existing for read, synchronous: SUCCESS, OPENED(1).
        let (st, h, action) = open_path(
            &mut k,
            &mut m,
            &mut tab,
            &mut t,
            b"game:\\data\\strings\\english.mo",
            0x0010_0081,
            1,
            0x20,
        );
        assert_eq!(st, STATUS_SUCCESS);
        assert_eq!(action, 1);
        assert_ne!(h, 0xFFFF_FFFF);
        // Read 3 bytes at offset 0: bytes delivered, IOSB 3.
        let buf = 0x8400_C000;
        let rio = 0x8400_C100;
        t.gpr[3] = h as u64;
        t.gpr[4] = 0;
        t.gpr[5] = 0;
        t.gpr[6] = 0;
        t.gpr[7] = rio as u64;
        t.gpr[8] = buf as u64;
        t.gpr[9] = 3;
        t.gpr[10] = 0;
        dispatch_import(
            &mut k,
            &mut m,
            &mut tab,
            7,
            &mut t,
            &imp("xboxkrnl.exe", 0xF0),
        )
        .unwrap();
        assert_eq!(t.gpr[3] as u32, STATUS_SUCCESS);
        assert_eq!(m.read_u32(rio + 4).unwrap(), 3);
        assert_eq!(m.read_bytes(buf, 3).unwrap(), &[9, 8, 7]);
        // Second read continues at position 3: 2 bytes left.
        t.gpr[3] = h as u64;
        t.gpr[4] = 0;
        t.gpr[5] = 0;
        t.gpr[6] = 0;
        t.gpr[7] = rio as u64;
        t.gpr[8] = buf as u64;
        t.gpr[9] = 16;
        t.gpr[10] = 0;
        dispatch_import(
            &mut k,
            &mut m,
            &mut tab,
            7,
            &mut t,
            &imp("xboxkrnl.exe", 0xF0),
        )
        .unwrap();
        assert_eq!(t.gpr[3] as u32, STATUS_SUCCESS);
        assert_eq!(m.read_u32(rio + 4).unwrap(), 2);
        // Third read hits EOF.
        t.gpr[3] = h as u64;
        t.gpr[4] = 0;
        t.gpr[5] = 0;
        t.gpr[6] = 0;
        t.gpr[7] = rio as u64;
        t.gpr[8] = buf as u64;
        t.gpr[9] = 16;
        t.gpr[10] = 0;
        dispatch_import(
            &mut k,
            &mut m,
            &mut tab,
            7,
            &mut t,
            &imp("xboxkrnl.exe", 0xF0),
        )
        .unwrap();
        assert_eq!(t.gpr[3] as u32, crate::fs::STATUS_END_OF_FILE);
        // Close, then read-after-close is INVALID_HANDLE.
        t.gpr[3] = h as u64;
        dispatch_import(
            &mut k,
            &mut m,
            &mut tab,
            7,
            &mut t,
            &imp("xboxkrnl.exe", 0xCF),
        )
        .unwrap();
        assert_eq!(t.gpr[3] as u32, STATUS_SUCCESS);
        t.gpr[3] = h as u64;
        t.gpr[4] = 0;
        t.gpr[5] = 0;
        t.gpr[6] = 0;
        t.gpr[7] = rio as u64;
        t.gpr[8] = buf as u64;
        t.gpr[9] = 3;
        t.gpr[10] = 0;
        dispatch_import(
            &mut k,
            &mut m,
            &mut tab,
            7,
            &mut t,
            &imp("xboxkrnl.exe", 0xF0),
        )
        .unwrap();
        assert_eq!(t.gpr[3] as u32, STATUS_INVALID_HANDLE);
        // Missing file, disposition OPEN: NOT_FOUND + invalid handle.
        let (st, h, _) = open_path(
            &mut k,
            &mut m,
            &mut tab,
            &mut t,
            b"game:\\nope.bin",
            0x0010_0081,
            1,
            0,
        );
        assert_eq!(st, crate::fs::STATUS_OBJECT_NAME_NOT_FOUND);
        assert_eq!(h, 0xFFFF_FFFF);
        // Write access on read-only backend: ACCESS_DENIED.
        let (st, h, _) = open_path(
            &mut k,
            &mut m,
            &mut tab,
            &mut t,
            b"game:\\data\\strings\\english.mo",
            0x4000_0000,
            1,
            0,
        );
        assert_eq!(st, crate::fs::STATUS_ACCESS_DENIED);
        assert_eq!(h, 0xFFFF_FFFF);
        // Bad characters: NAME_INVALID.
        let (st, _, _) = open_path(
            &mut k,
            &mut m,
            &mut tab,
            &mut t,
            b"game:\\a|b.bin",
            0x0010_0081,
            1,
            0,
        );
        assert_eq!(st, crate::fs::STATUS_OBJECT_NAME_INVALID);
        // Unknown device: PATH_NOT_FOUND.
        let (st, _, _) = open_path(
            &mut k,
            &mut m,
            &mut tab,
            &mut t,
            b"mu:\\save.bin",
            0x0010_0081,
            1,
            0,
        );
        assert_eq!(st, crate::fs::STATUS_OBJECT_PATH_NOT_FOUND);
        // Unknown close handle: INVALID_HANDLE.
        t.gpr[3] = 0xDEAD_BEEF;
        dispatch_import(
            &mut k,
            &mut m,
            &mut tab,
            7,
            &mut t,
            &imp("xboxkrnl.exe", 0xCF),
        )
        .unwrap();
        assert_eq!(t.gpr[3] as u32, STATUS_INVALID_HANDLE);
        // Non-synchronous open: reads report PENDING with valid IOSB
        // (reference sync-path shape), bytes still delivered.
        let (st, h2, _) = open_path(
            &mut k,
            &mut m,
            &mut tab,
            &mut t,
            b"game:\\data\\strings\\english.mo",
            0x0010_0081,
            1,
            0,
        );
        assert_eq!(st, STATUS_SUCCESS);
        t.gpr[3] = h2 as u64;
        t.gpr[4] = 0;
        t.gpr[5] = 0;
        t.gpr[6] = 0;
        t.gpr[7] = rio as u64;
        t.gpr[8] = buf as u64;
        t.gpr[9] = 2;
        t.gpr[10] = 0;
        dispatch_import(
            &mut k,
            &mut m,
            &mut tab,
            7,
            &mut t,
            &imp("xboxkrnl.exe", 0xF0),
        )
        .unwrap();
        assert_eq!(t.gpr[3] as u32, STATUS_PENDING);
        assert_eq!(m.read_u32(rio).unwrap(), STATUS_SUCCESS);
        assert_eq!(m.read_u32(rio + 4).unwrap(), 2);
        assert_eq!(m.read_bytes(buf, 2).unwrap(), &[9, 8]);
    }

    #[test]
    fn nt_query_info_file_shapes() {
        use crate::fs::FsLookup;
        use std::sync::Arc;
        let mut k = Kernel::new();
        let mut m = Memory::new();
        let mut tab = ImportTable::new();
        let mut t = thread();
        let bytes: Arc<[u8]> = Arc::from([1u8, 2, 3, 4, 5].as_slice());
        let (h, _) = k
            .file_open(
                "data/x.bin".to_string(),
                FsLookup::File(bytes),
                crate::fs::DISP_OPEN,
                0,
            )
            .expect("open");
        let info = 0x8400_D000;
        let iosb = 0x8400_D100;
        m.write_bytes(info, &[0xCCu8; 64]).unwrap();
        // NetworkOpen (34): size + attrs land at the reference offsets.
        t.gpr[3] = h as u64;
        t.gpr[4] = iosb as u64;
        t.gpr[5] = info as u64;
        t.gpr[6] = 56;
        t.gpr[7] = 34;
        dispatch_import(
            &mut k,
            &mut m,
            &mut tab,
            7,
            &mut t,
            &imp("xboxkrnl.exe", 0xE8),
        )
        .unwrap();
        assert_eq!(t.gpr[3] as u32, STATUS_SUCCESS);
        assert_eq!(m.read_u64(info + 40).unwrap(), 5);
        assert_eq!(m.read_u32(info + 48).unwrap(), 0x80);
        assert_eq!(m.read_u32(iosb + 4).unwrap(), 56);
        // Position (14): live offset (0 before any read).
        t.gpr[3] = h as u64;
        t.gpr[4] = iosb as u64;
        t.gpr[5] = info as u64;
        t.gpr[6] = 8;
        t.gpr[7] = 14;
        dispatch_import(
            &mut k,
            &mut m,
            &mut tab,
            7,
            &mut t,
            &imp("xboxkrnl.exe", 0xE8),
        )
        .unwrap();
        assert_eq!(t.gpr[3] as u32, STATUS_SUCCESS);
        assert_eq!(m.read_u64(info).unwrap(), 0);
        // Short buffer: MISMATCH, buffer untouched.
        m.write_bytes(info, &[0xCCu8; 8]).unwrap();
        t.gpr[3] = h as u64;
        t.gpr[4] = iosb as u64;
        t.gpr[5] = info as u64;
        t.gpr[6] = 4;
        t.gpr[7] = 14;
        dispatch_import(
            &mut k,
            &mut m,
            &mut tab,
            7,
            &mut t,
            &imp("xboxkrnl.exe", 0xE8),
        )
        .unwrap();
        assert_eq!(t.gpr[3] as u32, STATUS_INFO_LENGTH_MISMATCH);
        assert_eq!(m.read_bytes(info, 8).unwrap(), &[0xCCu8; 8]);
        // Unknown class: INVALID_INFO_CLASS.
        t.gpr[3] = h as u64;
        t.gpr[4] = iosb as u64;
        t.gpr[5] = info as u64;
        t.gpr[6] = 64;
        t.gpr[7] = 99;
        dispatch_import(
            &mut k,
            &mut m,
            &mut tab,
            7,
            &mut t,
            &imp("xboxkrnl.exe", 0xE8),
        )
        .unwrap();
        assert_eq!(t.gpr[3] as u32, STATUS_INVALID_INFO_CLASS);
        // Bad handle: INVALID_HANDLE.
        t.gpr[3] = 0xDEAD_BEEF;
        t.gpr[4] = iosb as u64;
        t.gpr[5] = info as u64;
        t.gpr[6] = 56;
        t.gpr[7] = 34;
        dispatch_import(
            &mut k,
            &mut m,
            &mut tab,
            7,
            &mut t,
            &imp("xboxkrnl.exe", 0xE8),
        )
        .unwrap();
        assert_eq!(t.gpr[3] as u32, STATUS_INVALID_HANDLE);
    }

    #[test]
    fn rtl_nt_status_to_dos_error_maps() {
        // Retail fault ordinal: RtlNtStatusToDosError(309).
        assert_eq!(
            ImportTable::name_of("xboxkrnl.exe", 0x135),
            Some("RtlNtStatusToDosError")
        );
        // Spot values verified against reference error_table_0xC0000001
        // / error_table_0x00000103.
        assert_eq!(nt_status_to_dos_error(0xC000_003A), 3); // PATH_NOT_FOUND
        assert_eq!(nt_status_to_dos_error(0xC000_0034), 2); // NAME_NOT_FOUND
        assert_eq!(nt_status_to_dos_error(0xC000_0022), 5); // ACCESS_DENIED
        assert_eq!(nt_status_to_dos_error(0xC000_0008), 6); // INVALID_HANDLE
        assert_eq!(nt_status_to_dos_error(0xC000_000D), 87); // INVALID_PARAMETER
        assert_eq!(nt_status_to_dos_error(0x0000_0103), 997); // PENDING
        assert_eq!(nt_status_to_dos_error(0), 0);
        assert_eq!(nt_status_to_dos_error(0xC000_0103), 267); // NOT_A_DIRECTORY
        assert_eq!(nt_status_to_dos_error(0xDEAD_BEEF), 317); // unmapped fallback
                                                              // Through dispatch: r3 in, r3 out.
        let mut k = Kernel::new();
        let mut m = Memory::new();
        let mut tab = ImportTable::new();
        let mut t = thread();
        t.gpr[3] = 0xC000_003A_u64;
        dispatch_import(
            &mut k,
            &mut m,
            &mut tab,
            0,
            &mut t,
            &imp("xboxkrnl.exe", 0x135),
        )
        .unwrap();
        assert_eq!(t.gpr[3] as u32, 3);
    }

    fn xmsg_ret(app: u32, message: u32) -> u32 {
        let mut t = thread();
        t.gpr[3] = app as u64;
        t.gpr[4] = message as u64;
        xmsg_in_process_call(app, message, &mut t).unwrap();
        t.gpr[3] as u32
    }

    #[test]
    fn xmsg_livebase_logon_status() {
        assert_eq!(
            ImportTable::name_of("xam.xex", 0x1F4),
            Some("XMsgInProcessCall")
        );
        // Retail dash call: app 0xFC (LiveBase), XLiveBaseLogonGetHR.
        assert_eq!(xmsg_ret(0xFC, 0x58003), 0x0015_10F1);
        assert_eq!(xmsg_ret(0xFC, 0x58006), 0x8015_1802);
        assert_eq!(xmsg_ret(0xFC, 0x58004), 0);
        assert_eq!(xmsg_ret(0xFC, 0xDEAD), 0x8000_4005);
        assert_eq!(xmsg_ret(0xFB, 0x58003), 0x8007_0002);
        // Through dispatch: r3=app, r4=message.
        let mut k = Kernel::new();
        let mut m = Memory::new();
        let mut tab = ImportTable::new();
        let mut t = thread();
        t.gpr[3] = 0xFC_u64;
        t.gpr[4] = 0x58003_u64;
        dispatch_import(&mut k, &mut m, &mut tab, 0, &mut t, &imp("xam.xex", 0x1F4)).unwrap();
        assert_eq!(t.gpr[3] as u32, 0x0015_10F1);
    }

    #[test]
    fn experience_mode_reports_full() {
        assert_eq!(
            ImportTable::name_of("xam.xex", 0x646),
            Some("XamPackageManagerGetExperienceMode")
        );
        let mut k = Kernel::new();
        let mut m = Memory::new();
        let mut tab = ImportTable::new();
        let mut t = thread();
        m.write_u32(0x4000, 1).unwrap();
        t.gpr[3] = 0x4000_u64;
        dispatch_import(&mut k, &mut m, &mut tab, 0, &mut t, &imp("xam.xex", 0x646)).unwrap();
        assert_eq!(t.gpr[3] as u32, 0);
        assert_eq!(m.read_u32(0x4000).unwrap(), 1);
        // Null output pointer is an explicit parameter error.
        t.gpr[3] = 0_u64;
        dispatch_import(&mut k, &mut m, &mut tab, 0, &mut t, &imp("xam.xex", 0x646)).unwrap();
        assert_eq!(t.gpr[3] as u32, 0x57);
    }

    #[test]
    fn flush_logon_queue_is_noop_success() {
        assert_eq!(
            ImportTable::name_of("xam.xex", 0x220),
            Some("XamUserFlushLogonQueue")
        );
        let mut k = Kernel::new();
        let mut m = Memory::new();
        let mut tab = ImportTable::new();
        let mut t = thread();
        t.gpr[3] = 0x9296_DAF8_u64;
        dispatch_import(&mut k, &mut m, &mut tab, 0, &mut t, &imp("xam.xex", 0x220)).unwrap();
        assert_eq!(t.gpr[3] as u32, 0);
    }

    #[test]
    fn language_reports_english() {
        let mut k = Kernel::new();
        let mut m = Memory::new();
        let mut tab = ImportTable::new();
        let mut t = thread();
        dispatch_import(&mut k, &mut m, &mut tab, 0, &mut t, &imp("xam.xex", 0x3D2)).unwrap();
        assert_eq!(t.gpr[3] as u32, 1);
    }

    #[test]
    fn locale_reports_us() {
        assert_eq!(ImportTable::name_of("xam.xex", 0x4A9), Some("XamGetLocale"));
        let mut k = Kernel::new();
        let mut m = Memory::new();
        let mut tab = ImportTable::new();
        let mut t = thread();
        dispatch_import(&mut k, &mut m, &mut tab, 0, &mut t, &imp("xam.xex", 0x4A9)).unwrap();
        assert_eq!(t.gpr[3] as u32, 36);
    }

    #[test]
    fn online_language_country_writes_xconfig() {
        let mut k = Kernel::new();
        let mut m = Memory::new();
        let mut tab = ImportTable::new();
        let mut t = thread();
        m.write_u8(0x4000, 0).unwrap();
        m.write_u8(0x4001, 0).unwrap();
        t.gpr[3] = 0_u64; // xuid: no signed-in user
        t.gpr[4] = 0x4000_u64;
        t.gpr[5] = 0x4001_u64;
        dispatch_import(&mut k, &mut m, &mut tab, 0, &mut t, &imp("xam.xex", 0x58B)).unwrap();
        assert_eq!(m.read_u8(0x4000).unwrap(), 1);
        assert_eq!(m.read_u8(0x4001).unwrap(), 103);
    }

    #[test]
    fn background_download_mode_is_noop_success() {
        let mut k = Kernel::new();
        let mut m = Memory::new();
        let mut tab = ImportTable::new();
        let mut t = thread();
        t.gpr[3] = 0_u64;
        dispatch_import(&mut k, &mut m, &mut tab, 0, &mut t, &imp("xam.xex", 0x9C4)).unwrap();
        assert_eq!(t.gpr[3] as u32, 0);
    }

    #[test]
    fn download_storage_callback_is_noop_success() {
        assert_eq!(
            ImportTable::name_of("xam.xex", 0x4E4),
            Some("XamBackgroundDownloadNetworkStorageRegisterChangeCallback")
        );
        let mut k = Kernel::new();
        let mut m = Memory::new();
        let mut tab = ImportTable::new();
        let mut t = thread();
        t.gpr[3] = 0x9226_0938_u64;
        dispatch_import(&mut k, &mut m, &mut tab, 0, &mut t, &imp("xam.xex", 0x4E4)).unwrap();
        assert_eq!(t.gpr[3] as u32, 0);
    }

    #[test]
    fn staging_mode_reports_retail() {
        assert_eq!(
            ImportTable::name_of("xam.xex", 0x76F),
            Some("XamGetStagingMode")
        );
        let mut k = Kernel::new();
        let mut m = Memory::new();
        let mut tab = ImportTable::new();
        let mut t = thread();
        dispatch_import(&mut k, &mut m, &mut tab, 0, &mut t, &imp("xam.xex", 0x76F)).unwrap();
        assert_eq!(t.gpr[3] as u32, 0);
    }

    #[test]
    fn fitness_clear_is_noop_success() {
        assert_eq!(
            ImportTable::name_of("xam.xex", 0x4C1),
            Some("XamFitnessClearBodyProfileRecords")
        );
        let mut k = Kernel::new();
        let mut m = Memory::new();
        let mut tab = ImportTable::new();
        let mut t = thread();
        dispatch_import(&mut k, &mut m, &mut tab, 0, &mut t, &imp("xam.xex", 0x4C1)).unwrap();
        assert_eq!(t.gpr[3] as u32, 0);
    }

    #[test]
    fn dash_context_set_get_roundtrip() {
        assert_eq!(
            ImportTable::name_of("xam.xex", 0x1CC),
            Some("XamSetDashContext")
        );
        let mut k = Kernel::new();
        let mut m = Memory::new();
        let mut tab = ImportTable::new();
        let mut t = thread();
        // Retail dash call writes 0 (already 0): no broadcast, returns 0.
        t.gpr[3] = 0_u64;
        dispatch_import(&mut k, &mut m, &mut tab, 0, &mut t, &imp("xam.xex", 0x1CC)).unwrap();
        assert_eq!(t.gpr[3] as u32, 0);
        assert_eq!(k.dash_context, 0);
        // A change stores and broadcasts; the getter reads it back.
        t.gpr[3] = 7_u64;
        dispatch_import(&mut k, &mut m, &mut tab, 0, &mut t, &imp("xam.xex", 0x1CC)).unwrap();
        assert_eq!(k.dash_context, 7);
        dispatch_import(&mut k, &mut m, &mut tab, 0, &mut t, &imp("xam.xex", 0x1CD)).unwrap();
        assert_eq!(t.gpr[3] as u32, 7);
    }

    #[test]
    fn launch_data_empty_reports_not_found() {
        let mut k = Kernel::new();
        let mut m = Memory::new();
        let mut tab = ImportTable::new();
        let mut t = thread();
        // Retail dash call against empty launch data.
        m.write_u32(0x4000, 0xDEAD_BEEF).unwrap();
        t.gpr[3] = 0x4000_u64;
        t.gpr[4] = 0x3FC_u64;
        dispatch_import(&mut k, &mut m, &mut tab, 0, &mut t, &imp("xam.xex", 0x1A8)).unwrap();
        assert_eq!(t.gpr[3] as u32, 2);
        assert_eq!(m.read_u32(0x4000).unwrap(), 0xDEAD_BEEF); // untouched
        t.gpr[3] = 0x4000_u64;
        dispatch_import(&mut k, &mut m, &mut tab, 0, &mut t, &imp("xam.xex", 0x1A7)).unwrap();
        assert_eq!(t.gpr[3] as u32, 2);
        assert_eq!(m.read_u32(0x4000).unwrap(), 0);
        // Set then serve back, truncated to the buffer.
        m.write_bytes(0x5000, &[9, 8, 7, 6]).unwrap();
        t.gpr[3] = 0x5000_u64;
        t.gpr[4] = 4_u64;
        dispatch_import(&mut k, &mut m, &mut tab, 0, &mut t, &imp("xam.xex", 0x1A6)).unwrap();
        assert_eq!(t.gpr[3] as u32, 0);
        t.gpr[3] = 0x4000_u64;
        dispatch_import(&mut k, &mut m, &mut tab, 0, &mut t, &imp("xam.xex", 0x1A7)).unwrap();
        assert_eq!(t.gpr[3] as u32, 0);
        assert_eq!(m.read_u32(0x4000).unwrap(), 4);
        t.gpr[3] = 0x6000_u64;
        t.gpr[4] = 2_u64;
        dispatch_import(&mut k, &mut m, &mut tab, 0, &mut t, &imp("xam.xex", 0x1A8)).unwrap();
        assert_eq!(t.gpr[3] as u32, 0);
        assert_eq!(m.read_bytes(0x6000, 2).unwrap(), &[9, 8]);
    }

    #[test]
    fn xdf_initialize_is_noop_success() {
        assert_eq!(
            ImportTable::name_of("xam.xex", 0x650),
            Some("XdfInitialize")
        );
        let mut k = Kernel::new();
        let mut m = Memory::new();
        let mut tab = ImportTable::new();
        let mut t = thread();
        dispatch_import(&mut k, &mut m, &mut tab, 0, &mut t, &imp("xam.xex", 0x650)).unwrap();
        assert_eq!(t.gpr[3] as u32, 0);
    }

    #[test]
    fn xam_video_mode_matches_vd_query() {
        assert_eq!(
            ImportTable::name_of("xam.xex", 0x3D1),
            Some("XGetVideoMode")
        );
        let mut k = Kernel::new();
        let mut m = Memory::new();
        let mut tab = ImportTable::new();
        let mut t = thread();
        t.gpr[3] = 0x4000_u64;
        dispatch_import(&mut k, &mut m, &mut tab, 0, &mut t, &imp("xam.xex", 0x3D1)).unwrap();
        t.gpr[3] = 0x5000_u64;
        dispatch_import(
            &mut k,
            &mut m,
            &mut tab,
            0,
            &mut t,
            &imp("xboxkrnl.exe", 0x1CA),
        )
        .unwrap();
        assert_eq!(
            m.read_bytes(0x4000, 48).unwrap(),
            m.read_bytes(0x5000, 48).unwrap()
        );
        assert_eq!(m.read_u32(0x4000).unwrap(), 1280);
        assert_eq!(m.read_u32(0x4004).unwrap(), 720);
    }

    #[test]
    fn backstack_empty_returns_success_untouched() {
        assert_eq!(
            ImportTable::name_of("xam.xex", 0x7DC),
            Some("XamGetDashBackstackData")
        );
        let mut k = Kernel::new();
        let mut m = Memory::new();
        let mut tab = ImportTable::new();
        let mut t = thread();
        m.write_bytes(0x4000, &[0xCCu8; 16]).unwrap();
        m.write_u32(0x5000, 4).unwrap();
        t.gpr[3] = 0x4000_u64;
        t.gpr[4] = 0x5000_u64;
        dispatch_import(&mut k, &mut m, &mut tab, 0, &mut t, &imp("xam.xex", 0x7DC)).unwrap();
        assert_eq!(t.gpr[3] as u32, 0);
        assert_eq!(m.read_bytes(0x4000, 16).unwrap(), &[0xCCu8; 16]);
        assert_eq!(m.read_u32(0x5000).unwrap(), 4);
    }

    #[test]
    fn studio_rgb_mode_records() {
        assert_eq!(
            ImportTable::name_of("xboxkrnl.exe", 0x379),
            Some("VdSetStudioRGBMode")
        );
        let mut k = Kernel::new();
        let mut m = Memory::new();
        let mut tab = ImportTable::new();
        let mut t = thread();
        t.gpr[3] = 0x24_u64;
        dispatch_import(
            &mut k,
            &mut m,
            &mut tab,
            0,
            &mut t,
            &imp("xboxkrnl.exe", 0x379),
        )
        .unwrap();
        assert_eq!(t.gpr[3] as u32, 0);
        assert_eq!(k.vd_studio_rgb, Some(0x24));
    }

    #[test]
    fn fsc_cache_counts_stub_zero() {
        let mut k = Kernel::new();
        let mut m = Memory::new();
        let mut tab = ImportTable::new();
        let mut t = thread();
        // Retail dash call: FscSetCacheElementCount(0, 0x100).
        t.gpr[3] = 0_u64;
        t.gpr[4] = 0x100_u64;
        dispatch_import(
            &mut k,
            &mut m,
            &mut tab,
            0,
            &mut t,
            &imp("xboxkrnl.exe", 0x21),
        )
        .unwrap();
        assert_eq!(t.gpr[3] as u32, 0);
        dispatch_import(
            &mut k,
            &mut m,
            &mut tab,
            0,
            &mut t,
            &imp("xboxkrnl.exe", 0x20),
        )
        .unwrap();
        assert_eq!(t.gpr[3] as u32, 0);
    }

    #[test]
    fn hal_av_pack_reports_hdmi() {
        assert_eq!(
            ImportTable::name_of("xboxkrnl.exe", 0x22),
            Some("HalGetCurrentAVPack")
        );
        let mut k = Kernel::new();
        let mut m = Memory::new();
        let mut tab = ImportTable::new();
        let mut t = thread();
        dispatch_import(
            &mut k,
            &mut m,
            &mut tab,
            0,
            &mut t,
            &imp("xboxkrnl.exe", 0x22),
        )
        .unwrap();
        assert_eq!(t.gpr[3] as u32, 8);
    }

    #[test]
    fn dpc_initializes_routine_context() {
        let mut k = Kernel::new();
        let mut m = Memory::new();
        let mut tab = ImportTable::new();
        let mut t = thread();
        m.write_bytes(0x4000, &[0xCCu8; 28]).unwrap();
        t.gpr[3] = 0x4000_u64;
        t.gpr[4] = 0x921C_89B0_u64;
        t.gpr[5] = 0x0103_51A4_u64;
        dispatch_import(
            &mut k,
            &mut m,
            &mut tab,
            0,
            &mut t,
            &imp("xboxkrnl.exe", 0x6F),
        )
        .unwrap();
        assert_eq!(m.read_bytes(0x4000, 2).unwrap(), &[0, 19]); // type u16be
        assert_eq!(m.read_u8(0x4002).unwrap(), 0);
        assert_eq!(m.read_u8(0x4003).unwrap(), 0);
        assert_eq!(m.read_u32(0x400C).unwrap(), 0x921C_89B0);
        assert_eq!(m.read_u32(0x4010).unwrap(), 0x0103_51A4);
    }

    #[test]
    fn symlink_registers_and_strips_qualifier() {
        assert_eq!(
            ImportTable::name_of("xboxkrnl.exe", 0x103),
            Some("ObCreateSymbolicLink")
        );
        let mut k = Kernel::new();
        let mut m = Memory::new();
        let mut tab = ImportTable::new();
        let mut t = thread();
        // OA + ANSI + bytes laid out in guest memory.
        fn ansi(m: &mut Memory, at: u32, s: &[u8]) {
            m.write_bytes(at, &(s.len() as u16).to_be_bytes()).unwrap();
            m.write_bytes(at + 2, &(s.len() as u16).to_be_bytes())
                .unwrap();
            m.write_u32(at + 4, at + 8).unwrap();
            m.write_bytes(at + 8, s).unwrap();
        }
        ansi(&mut m, 0x4000, b"\\??\\D:");
        ansi(&mut m, 0x4100, b"\\Device\\Harddisk0\\Partition1");
        t.gpr[3] = 0x4000_u64;
        t.gpr[4] = 0x4100_u64;
        dispatch_import(
            &mut k,
            &mut m,
            &mut tab,
            0,
            &mut t,
            &imp("xboxkrnl.exe", 0x103),
        )
        .unwrap();
        assert_eq!(t.gpr[3] as u32, 0);
        assert_eq!(
            k.symlinks.get("d:").map(String::as_str),
            Some("\\device\\harddisk0\\partition1")
        );
        // Re-registering the same mapping is still success.
        t.gpr[3] = 0x4000_u64;
        t.gpr[4] = 0x4100_u64;
        dispatch_import(
            &mut k,
            &mut m,
            &mut tab,
            0,
            &mut t,
            &imp("xboxkrnl.exe", 0x103),
        )
        .unwrap();
        assert_eq!(t.gpr[3] as u32, 0);
    }

    #[test]
    fn erw_lock_exclusive_roundtrip() {
        // Retail dash lock: init then acquire/release.
        let mut k = Kernel::new();
        let mut m = Memory::new();
        let mut tab = ImportTable::new();
        let mut t = thread();
        let lock = 0x5000u32;
        m.write_bytes(lock, &[0xAAu8; 0x38]).unwrap();
        let call = |k: &mut Kernel,
                    m: &mut Memory,
                    tab: &mut ImportTable,
                    t: &mut ThreadState,
                    ord: u16| {
            t.gpr[3] = lock as u64;
            dispatch_import(k, m, tab, 0, t, &imp("xboxkrnl.exe", ord))
        };
        call(&mut k, &mut m, &mut tab, &mut t, 0x11).unwrap();
        assert_eq!(m.read_u32(lock).unwrap(), 0xFFFF_FFFF); // -1
        assert_eq!(m.read_u8(lock + 16).unwrap(), 1); // sync event
        assert_eq!(m.read_u32(lock + 20).unwrap(), 0);
        assert_eq!(m.read_u8(lock + 32).unwrap(), 5); // semaphore
        assert_eq!(m.read_u32(lock + 48).unwrap(), 0x7FFF_FFFF);
        // Exclusive acquire fast path: -1 -> 0.
        call(&mut k, &mut m, &mut tab, &mut t, 0x07).unwrap();
        assert_eq!(m.read_u32(lock).unwrap(), 0);
        // Contended exclusive acquire is explicit, never silent.
        let e = call(&mut k, &mut m, &mut tab, &mut t, 0x07)
            .unwrap_err()
            .to_string();
        assert!(e.contains("would block"), "got: {}", e);
        // Clean roundtrip from a fresh init.
        call(&mut k, &mut m, &mut tab, &mut t, 0x11).unwrap();
        call(&mut k, &mut m, &mut tab, &mut t, 0x07).unwrap();
        call(&mut k, &mut m, &mut tab, &mut t, 0x16).unwrap();
        assert_eq!(m.read_u32(lock).unwrap(), 0xFFFF_FFFF);
        assert_eq!(m.read_u32(lock + 12).unwrap(), 0);
        // Shared acquire/release pair.
        call(&mut k, &mut m, &mut tab, &mut t, 0x08).unwrap();
        assert_eq!(m.read_u32(lock + 12).unwrap(), 1);
        call(&mut k, &mut m, &mut tab, &mut t, 0x16).unwrap();
        assert_eq!(m.read_u32(lock).unwrap(), 0xFFFF_FFFF);
        // Try-exclusive: 1 when free, 0 when held.
        t.gpr[3] = lock as u64;
        dispatch_import(
            &mut k,
            &mut m,
            &mut tab,
            0,
            &mut t,
            &imp("xboxkrnl.exe", 0x2DD),
        )
        .unwrap();
        assert_eq!(t.gpr[3] as u32, 1);
        t.gpr[3] = lock as u64;
        dispatch_import(
            &mut k,
            &mut m,
            &mut tab,
            0,
            &mut t,
            &imp("xboxkrnl.exe", 0x2DD),
        )
        .unwrap();
        assert_eq!(t.gpr[3] as u32, 0);
        call(&mut k, &mut m, &mut tab, &mut t, 0x16).unwrap();
        // Try-shared on a free lock acquires.
        t.gpr[3] = lock as u64;
        dispatch_import(
            &mut k,
            &mut m,
            &mut tab,
            0,
            &mut t,
            &imp("xboxkrnl.exe", 0x2DE),
        )
        .unwrap();
        assert_eq!(t.gpr[3] as u32, 1);
        assert_eq!(m.read_u32(lock + 12).unwrap(), 1);
    }

    #[test]
    fn etx_producer_register_is_noop_success() {
        assert_eq!(
            ImportTable::name_of("xboxkrnl.exe", 0x334),
            Some("EtxProducerRegister")
        );
        let mut k = Kernel::new();
        let mut m = Memory::new();
        let mut tab = ImportTable::new();
        let mut t = thread();
        t.gpr[3] = 0x9201_C9F0_u64;
        dispatch_import(
            &mut k,
            &mut m,
            &mut tab,
            0,
            &mut t,
            &imp("xboxkrnl.exe", 0x334),
        )
        .unwrap();
        assert_eq!(t.gpr[3] as u32, 0);
    }

    #[test]
    fn usbcam_reports_not_connected() {
        assert_eq!(
            ImportTable::name_of("xboxkrnl.exe", 0x21D),
            Some("XUsbcamGetState")
        );
        let mut k = Kernel::new();
        let mut m = Memory::new();
        let mut tab = ImportTable::new();
        let mut t = thread();
        dispatch_import(
            &mut k,
            &mut m,
            &mut tab,
            0,
            &mut t,
            &imp("xboxkrnl.exe", 0x21D),
        )
        .unwrap();
        assert_eq!(t.gpr[3] as u32, 0);
    }

    #[test]
    fn crypt_random_fills_fd() {
        assert_eq!(
            ImportTable::name_of("xboxkrnl.exe", 0x18A),
            Some("XeCryptRandom")
        );
        let mut k = Kernel::new();
        let mut m = Memory::new();
        let mut tab = ImportTable::new();
        let mut t = thread();
        m.write_bytes(0x4000, &[0u8; 16]).unwrap();
        t.gpr[3] = 0x4000_u64;
        t.gpr[4] = 0x10_u64;
        dispatch_import(
            &mut k,
            &mut m,
            &mut tab,
            0,
            &mut t,
            &imp("xboxkrnl.exe", 0x18A),
        )
        .unwrap();
        assert_eq!(m.read_bytes(0x4000, 16).unwrap(), &[0xFD; 16]);
        // Zero length touches nothing and still succeeds.
        t.gpr[3] = 0x4000_u64;
        t.gpr[4] = 0_u64;
        dispatch_import(
            &mut k,
            &mut m,
            &mut tab,
            0,
            &mut t,
            &imp("xboxkrnl.exe", 0x18A),
        )
        .unwrap();
    }

    #[test]
    fn critical_region_nests() {
        let mut k = Kernel::new();
        let mut m = Memory::new();
        let mut tab = ImportTable::new();
        let mut t = thread();
        assert_eq!(
            ImportTable::name_of("xboxkrnl.exe", 0x5F),
            Some("KeEnterCriticalRegion")
        );
        assert_eq!(
            ImportTable::name_of("xboxkrnl.exe", 0x7D),
            Some("KeLeaveCriticalRegion")
        );
        dispatch_import(
            &mut k,
            &mut m,
            &mut tab,
            0,
            &mut t,
            &imp("xboxkrnl.exe", 0x5F),
        )
        .unwrap();
        dispatch_import(
            &mut k,
            &mut m,
            &mut tab,
            0,
            &mut t,
            &imp("xboxkrnl.exe", 0x5F),
        )
        .unwrap();
        assert_eq!(k.critical_region, 2);
        dispatch_import(
            &mut k,
            &mut m,
            &mut tab,
            0,
            &mut t,
            &imp("xboxkrnl.exe", 0x7D),
        )
        .unwrap();
        assert_eq!(k.critical_region, 1);
    }

    #[test]
    fn nt_sync_objects_roundtrip() {
        let mut k = Kernel::new();
        let mut m = Memory::new();
        let mut tab = ImportTable::new();
        let mut t = thread();
        // NtCreateEvent(manual=0..., auto type=1, initial=0).
        let hp = 0x8400_4000;
        t.gpr[3] = hp as u64;
        t.gpr[4] = 0;
        t.gpr[5] = 1;
        t.gpr[6] = 0;
        dispatch_import(
            &mut k,
            &mut m,
            &mut tab,
            7,
            &mut t,
            &imp("xboxkrnl.exe", 0xD1),
        )
        .unwrap();
        assert_eq!(t.gpr[3] as u32, STATUS_SUCCESS);
        let ev = m.read_u32(hp).unwrap();
        assert_ne!(ev, 0);
        // Not signaled: wait times out.
        t.gpr[3] = ev as u64;
        t.gpr[4] = 0;
        t.gpr[5] = 0;
        t.gpr[6] = 0;
        dispatch_import(
            &mut k,
            &mut m,
            &mut tab,
            7,
            &mut t,
            &imp("xboxkrnl.exe", 0xFD),
        )
        .unwrap();
        assert_eq!(t.gpr[3] as u32, STATUS_TIMEOUT);
        // Set then wait succeeds (auto-reset consumes).
        t.gpr[3] = ev as u64;
        t.gpr[4] = 0;
        dispatch_import(
            &mut k,
            &mut m,
            &mut tab,
            7,
            &mut t,
            &imp("xboxkrnl.exe", 0xF6),
        )
        .unwrap();
        assert_eq!(t.gpr[3] as u32, STATUS_SUCCESS);
        t.gpr[3] = ev as u64;
        t.gpr[4] = 0;
        t.gpr[5] = 0;
        t.gpr[6] = 0;
        dispatch_import(
            &mut k,
            &mut m,
            &mut tab,
            7,
            &mut t,
            &imp("xboxkrnl.exe", 0xFD),
        )
        .unwrap();
        assert_eq!(t.gpr[3] as u32, STATUS_SUCCESS);
        // Second wait times out again (consumed).
        t.gpr[3] = ev as u64;
        t.gpr[4] = 0;
        t.gpr[5] = 0;
        t.gpr[6] = 0;
        dispatch_import(
            &mut k,
            &mut m,
            &mut tab,
            7,
            &mut t,
            &imp("xboxkrnl.exe", 0xFD),
        )
        .unwrap();
        assert_eq!(t.gpr[3] as u32, STATUS_TIMEOUT);
        // Semaphore: create(1/2), wait consumes, release restores.
        let sp = 0x8400_4010;
        t.gpr[3] = sp as u64;
        t.gpr[4] = 0;
        t.gpr[5] = 1;
        t.gpr[6] = 2;
        dispatch_import(
            &mut k,
            &mut m,
            &mut tab,
            7,
            &mut t,
            &imp("xboxkrnl.exe", 0xD5),
        )
        .unwrap();
        assert_eq!(t.gpr[3] as u32, STATUS_SUCCESS);
        let sem = m.read_u32(sp).unwrap();
        t.gpr[3] = sem as u64;
        t.gpr[4] = 0;
        t.gpr[5] = 0;
        t.gpr[6] = 0;
        dispatch_import(
            &mut k,
            &mut m,
            &mut tab,
            7,
            &mut t,
            &imp("xboxkrnl.exe", 0xFD),
        )
        .unwrap();
        assert_eq!(t.gpr[3] as u32, STATUS_SUCCESS);
        t.gpr[3] = sem as u64;
        t.gpr[4] = 0;
        t.gpr[5] = 0;
        t.gpr[6] = 0;
        dispatch_import(
            &mut k,
            &mut m,
            &mut tab,
            7,
            &mut t,
            &imp("xboxkrnl.exe", 0xFD),
        )
        .unwrap();
        assert_eq!(t.gpr[3] as u32, STATUS_TIMEOUT);
        let pp = 0x8400_4020;
        t.gpr[3] = sem as u64;
        t.gpr[4] = 1;
        t.gpr[5] = pp as u64;
        dispatch_import(
            &mut k,
            &mut m,
            &mut tab,
            7,
            &mut t,
            &imp("xboxkrnl.exe", 0xF3),
        )
        .unwrap();
        assert_eq!(t.gpr[3] as u32, STATUS_SUCCESS);
        assert_eq!(m.read_u32(pp).unwrap(), 0);
        // Over-release past the limit reports the limit status.
        t.gpr[3] = sem as u64;
        t.gpr[4] = 5;
        t.gpr[5] = pp as u64;
        dispatch_import(
            &mut k,
            &mut m,
            &mut tab,
            7,
            &mut t,
            &imp("xboxkrnl.exe", 0xF3),
        )
        .unwrap();
        assert_eq!(t.gpr[3] as u32, STATUS_SEMAPHORE_LIMIT_EXCEEDED);
        // Bad count at creation is INVALID_PARAMETER with a zero handle.
        t.gpr[3] = sp as u64;
        t.gpr[4] = 0;
        t.gpr[5] = 5;
        t.gpr[6] = 2;
        dispatch_import(
            &mut k,
            &mut m,
            &mut tab,
            7,
            &mut t,
            &imp("xboxkrnl.exe", 0xD5),
        )
        .unwrap();
        assert_eq!(t.gpr[3] as u32, STATUS_INVALID_PARAMETER);
        assert_eq!(m.read_u32(sp).unwrap(), 0);
        // Mutant: create unowned, wait owns, release frees.
        let mp = 0x8400_4030;
        t.gpr[3] = mp as u64;
        t.gpr[4] = 0;
        t.gpr[5] = 0;
        dispatch_import(
            &mut k,
            &mut m,
            &mut tab,
            7,
            &mut t,
            &imp("xboxkrnl.exe", 0xD4),
        )
        .unwrap();
        assert_eq!(t.gpr[3] as u32, STATUS_SUCCESS);
        let mu = m.read_u32(mp).unwrap();
        t.gpr[3] = mu as u64;
        t.gpr[4] = 0;
        t.gpr[5] = 0;
        t.gpr[6] = 0;
        dispatch_import(
            &mut k,
            &mut m,
            &mut tab,
            7,
            &mut t,
            &imp("xboxkrnl.exe", 0xFD),
        )
        .unwrap();
        assert_eq!(t.gpr[3] as u32, STATUS_SUCCESS);
        t.gpr[3] = mu as u64;
        dispatch_import(
            &mut k,
            &mut m,
            &mut tab,
            7,
            &mut t,
            &imp("xboxkrnl.exe", 0xF2),
        )
        .unwrap();
        // Recursion was 2 (create-unowned + one wait by same thread
        // stays 1... here wait took it to 1, release frees it).
        assert!(t.gpr[3] as u32 == STATUS_SUCCESS || t.gpr[3] as u32 == STATUS_MUTANT_NOT_OWNED);
        // Bad handle waits are INVALID_HANDLE, never success.
        t.gpr[3] = 0xDEAD_BEEF;
        t.gpr[4] = 0;
        t.gpr[5] = 0;
        t.gpr[6] = 0;
        dispatch_import(
            &mut k,
            &mut m,
            &mut tab,
            7,
            &mut t,
            &imp("xboxkrnl.exe", 0xFD),
        )
        .unwrap();
        assert_eq!(t.gpr[3] as u32, STATUS_INVALID_HANDLE);
    }

    #[test]
    fn crit_init_enter_leave() {
        let mut k = Kernel::new();
        let mut m = Memory::new();
        let mut tab = ImportTable::new();
        let mut t = thread();
        let cs = 0x8400_1000;
        m.write_bytes(cs, &[0u8; 28]).unwrap();
        t.gpr[3] = (cs) as u64;
        dispatch_import(
            &mut k,
            &mut m,
            &mut tab,
            1,
            &mut t,
            &imp("xboxkrnl.exe", 0x12E),
        )
        .unwrap();
        assert_eq!(m.read_u32(cs + CS_LOCK).unwrap(), 0xFFFF_FFFF);
        t.gpr[3] = (cs) as u64;
        dispatch_import(
            &mut k,
            &mut m,
            &mut tab,
            1,
            &mut t,
            &imp("xboxkrnl.exe", 0x125),
        )
        .unwrap();
        assert_eq!(m.read_u32(cs + CS_OWNER).unwrap(), 1);
        t.gpr[3] = (cs) as u64;
        dispatch_import(
            &mut k,
            &mut m,
            &mut tab,
            1,
            &mut t,
            &imp("xboxkrnl.exe", 0x130),
        )
        .unwrap();
        assert_eq!(m.read_u32(cs + CS_OWNER).unwrap(), 0);
    }

    #[test]
    fn perf_freq_returns_value_in_r3() {
        // The game wrapper stores r3 over the frequency slot, so r3
        // must carry the frequency (reference returns it).
        let mut k = Kernel::new();
        let mut m = Memory::new();
        let mut tab = ImportTable::new();
        let mut t = thread();
        let out = 0x8400_2000;
        t.gpr[3] = (out) as u64;
        dispatch_import(
            &mut k,
            &mut m,
            &mut tab,
            0,
            &mut t,
            &imp("xboxkrnl.exe", 0x83),
        )
        .unwrap();
        assert_eq!(m.read_u32(out).unwrap(), 50_000_000);
        assert_eq!((t.gpr[3] as u32), 50_000_000);
    }

    #[test]
    fn wsa_startup_fills_wsadata() {
        let mut k = Kernel::new();
        let mut m = Memory::new();
        let mut tab = ImportTable::new();
        let mut t = thread();
        let out = 0x8400_3000;
        t.gpr[4] = 0x0202_u64;
        t.gpr[5] = (out) as u64;
        dispatch_import(&mut k, &mut m, &mut tab, 0, &mut t, &imp("xam.xex", 0x1)).unwrap();
        assert_eq!((t.gpr[3] as u32), 0);
        assert_eq!(read_u16be(&m, out).unwrap(), 0x0202);
        assert_eq!(read_u16be(&m, out + 2).unwrap(), 0x0202);
        assert_eq!(m.read_u32(out + 4).unwrap(), 0);
    }

    #[test]
    fn pool_alloc_free_roundtrip() {
        let mut k = Kernel::new();
        let mut m = Memory::new();
        let mut tab = ImportTable::new();
        let mut t = thread();
        t.gpr[3] = 64_u64;
        dispatch_import(
            &mut k,
            &mut m,
            &mut tab,
            0,
            &mut t,
            &imp("xboxkrnl.exe", 0x09),
        )
        .unwrap();
        let a = t.gpr[3] as u32;
        assert_ne!(a, 0);
        assert_eq!(&m.read_bytes(a, 4).unwrap(), &[0, 0, 0, 0]);
        t.gpr[3] = (a) as u64;
        dispatch_import(
            &mut k,
            &mut m,
            &mut tab,
            0,
            &mut t,
            &imp("xboxkrnl.exe", 0x0F),
        )
        .unwrap();
    }

    #[test]
    fn tls_roundtrip() {
        let mut k = Kernel::new();
        let mut m = Memory::new();
        let mut tab = ImportTable::new();
        let mut t = thread();
        dispatch_import(
            &mut k,
            &mut m,
            &mut tab,
            0,
            &mut t,
            &imp("xboxkrnl.exe", 0x152),
        )
        .unwrap();
        let slot = t.gpr[3] as u32;
        assert!(slot < 64);
        t.gpr[3] = (slot) as u64;
        t.gpr[4] = 0x1234_5678_u64;
        dispatch_import(
            &mut k,
            &mut m,
            &mut tab,
            0,
            &mut t,
            &imp("xboxkrnl.exe", 0x155),
        )
        .unwrap();
        assert_eq!((t.gpr[3] as u32), 1);
        t.gpr[3] = (slot) as u64;
        dispatch_import(
            &mut k,
            &mut m,
            &mut tab,
            0,
            &mut t,
            &imp("xboxkrnl.exe", 0x154),
        )
        .unwrap();
        assert_eq!((t.gpr[3] as u32), 0x1234_5678);
    }

    #[test]
    fn header_field_from_placed_copy() {
        let mut k = Kernel::new();
        let mut m = Memory::new();
        let mut tab = ImportTable::new();
        let mut t = thread();
        // Minimal header: one inline entry 0x00020401 = 0x00A00000.
        let mut hdr = vec![0u8; 32];
        hdr[0..4].copy_from_slice(b"XEX2");
        hdr[20..24].copy_from_slice(&1u32.to_be_bytes());
        hdr[24..28].copy_from_slice(&0x0002_0401u32.to_be_bytes());
        hdr[28..32].copy_from_slice(&0x00A0_0000u32.to_be_bytes());
        k.set_module_info(0x8200_0000, 0x100, 0x5841_08CE);
        k.set_xex_header(hdr, 0x8200_1000, "default.xex".into());
        let placed = k.place_xex_header(&mut m).unwrap();
        assert_ne!(placed, 0x8200_0000);
        // Query through the placed copy, as games do via the module struct.
        t.gpr[3] = placed as u64;
        t.gpr[4] = 0x0002_0401_u64;
        dispatch_import(
            &mut k,
            &mut m,
            &mut tab,
            0,
            &mut t,
            &imp("xboxkrnl.exe", 0x12B),
        )
        .unwrap();
        assert_eq!((t.gpr[3] as u32), 0x00A0_0000);
        // Unknown header pointer stays 0, never fabricated.
        t.gpr[3] = 0x1234_5678_u64;
        dispatch_import(
            &mut k,
            &mut m,
            &mut tab,
            0,
            &mut t,
            &imp("xboxkrnl.exe", 0x12B),
        )
        .unwrap();
        assert_eq!((t.gpr[3] as u32), 0);
    }

    #[test]
    fn privilege_tests_flag_bit() {
        let mut k = Kernel::new();
        let mut m = Memory::new();
        let mut tab = ImportTable::new();
        let mut t = thread();
        // Bit 6 = INSECURE_SOCKETS.
        k.set_system_flags(0x40);
        t.gpr[3] = 6;
        dispatch_import(
            &mut k,
            &mut m,
            &mut tab,
            0,
            &mut t,
            &imp("xboxkrnl.exe", 0x194),
        )
        .unwrap();
        assert_eq!((t.gpr[3] as u32), 1);
        t.gpr[3] = 7;
        dispatch_import(
            &mut k,
            &mut m,
            &mut tab,
            0,
            &mut t,
            &imp("xboxkrnl.exe", 0x194),
        )
        .unwrap();
        assert_eq!((t.gpr[3] as u32), 0);
        // Out-of-range privilege is 0, never a shift panic.
        t.gpr[3] = 33;
        dispatch_import(
            &mut k,
            &mut m,
            &mut tab,
            0,
            &mut t,
            &imp("xboxkrnl.exe", 0x194),
        )
        .unwrap();
        assert_eq!((t.gpr[3] as u32), 0);
    }

    #[test]
    fn xnotify_listener_queue() {
        let mut k = Kernel::new();
        let mut m = Memory::new();
        let mut tab = ImportTable::new();
        let mut t = thread();
        // Create with mask bit 3, version 10.
        t.gpr[3] = 0x08;
        t.gpr[4] = 10;
        dispatch_import(&mut k, &mut m, &mut tab, 0, &mut t, &imp("xam.xex", 0x28A)).unwrap();
        let h = t.gpr[3] as u32;
        assert_ne!(h, 0);
        // Broadcast id with mask_index 3, version 2, data 0x77.
        let id = (3u32 << 25) | (2u32 << 16) | 0x41;
        t.gpr[3] = id as u64;
        t.gpr[4] = 0x77;
        dispatch_import(&mut k, &mut m, &mut tab, 0, &mut t, &imp("xam.xex", 0x28E)).unwrap();
        assert_eq!(t.gpr[3] as u32, 0);
        // GetNext (match 0) dequeues it.
        let ip = 0x8400_9000;
        let pp = 0x8400_9004;
        t.gpr[3] = h as u64;
        t.gpr[4] = 0;
        t.gpr[5] = ip as u64;
        t.gpr[6] = pp as u64;
        dispatch_import(&mut k, &mut m, &mut tab, 0, &mut t, &imp("xam.xex", 0x28B)).unwrap();
        assert_eq!(t.gpr[3] as u32, 1);
        assert_eq!(m.read_u32(ip).unwrap(), id);
        assert_eq!(m.read_u32(pp).unwrap(), 0x77);
        // Queue now empty: 0 with zeroed words.
        t.gpr[3] = h as u64;
        t.gpr[4] = 0;
        t.gpr[5] = ip as u64;
        t.gpr[6] = pp as u64;
        dispatch_import(&mut k, &mut m, &mut tab, 0, &mut t, &imp("xam.xex", 0x28B)).unwrap();
        assert_eq!(t.gpr[3] as u32, 0);
        assert_eq!(m.read_u32(ip).unwrap(), 0);
        // Wrong-area broadcast (mask_index 5) never arrives.
        let id2 = (5u32 << 25) | (1u32 << 16) | 0x07;
        t.gpr[3] = id2 as u64;
        t.gpr[4] = 0x99;
        dispatch_import(&mut k, &mut m, &mut tab, 0, &mut t, &imp("xam.xex", 0x28E)).unwrap();
        t.gpr[3] = h as u64;
        t.gpr[4] = id2 as u64;
        t.gpr[5] = ip as u64;
        t.gpr[6] = pp as u64;
        dispatch_import(&mut k, &mut m, &mut tab, 0, &mut t, &imp("xam.xex", 0x28B)).unwrap();
        assert_eq!(t.gpr[3] as u32, 0);
        // Unknown handle: 0.
        t.gpr[3] = 0xDEAD_BEEF;
        t.gpr[4] = 0;
        t.gpr[5] = ip as u64;
        t.gpr[6] = pp as u64;
        dispatch_import(&mut k, &mut m, &mut tab, 0, &mut t, &imp("xam.xex", 0x28B)).unwrap();
        assert_eq!(t.gpr[3] as u32, 0);
    }

    #[test]
    fn xam_content_license_mask() {
        let mut k = Kernel::new();
        let mut m = Memory::new();
        let mut tab = ImportTable::new();
        let mut t = thread();
        let out = 0x8400_A000;
        t.gpr[3] = out as u64;
        t.gpr[4] = 0;
        dispatch_import(&mut k, &mut m, &mut tab, 0, &mut t, &imp("xam.xex", 0x266)).unwrap();
        assert_eq!(t.gpr[3] as u32, 0);
        assert_eq!(m.read_u32(out).unwrap(), 1);
        // Null mask pointer is INVALID_PARAMETER.
        t.gpr[3] = 0;
        t.gpr[4] = 0;
        dispatch_import(&mut k, &mut m, &mut tab, 0, &mut t, &imp("xam.xex", 0x266)).unwrap();
        assert_eq!(t.gpr[3] as u32, 0x57);
    }

    #[test]
    fn xam_info_getters() {
        let mut k = Kernel::new();
        let mut m = Memory::new();
        let mut tab = ImportTable::new();
        let mut t = thread();
        k.set_module_info(0x8200_0000, 0x1000, 0x5841_08CE);
        dispatch_import(&mut k, &mut m, &mut tab, 0, &mut t, &imp("xam.xex", 0x3CB)).unwrap();
        assert_eq!((t.gpr[3] as u32), 8);
        dispatch_import(&mut k, &mut m, &mut tab, 0, &mut t, &imp("xam.xex", 0x282)).unwrap();
        assert_eq!((t.gpr[3] as u32), 0);
        dispatch_import(&mut k, &mut m, &mut tab, 0, &mut t, &imp("xam.xex", 0x1CF)).unwrap();
        assert_eq!((t.gpr[3] as u32), 0x5841_08CE);
        dispatch_import(&mut k, &mut m, &mut tab, 0, &mut t, &imp("xam.xex", 0x3CC)).unwrap();
        assert_eq!((t.gpr[3] as u32), 0x03FF);
        assert_eq!(ImportTable::name_of("xam.xex", 0x3CB), Some("XGetAVPack"));
    }

    #[test]
    fn unimplemented_names_ordinal() {
        let mut k = Kernel::new();
        let mut m = Memory::new();
        let mut tab = ImportTable::new();
        let mut t = thread();
        let e = dispatch_import(
            &mut k,
            &mut m,
            &mut tab,
            0,
            &mut t,
            &imp("xboxkrnl.exe", 0x1A6),
        )
        .unwrap_err();
        assert!(format!("{}", e).contains("DbgLoadImageSymbols"));
    }
}
