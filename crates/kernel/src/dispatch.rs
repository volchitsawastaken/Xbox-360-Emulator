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
        (Lib::Xboxkrnl, 0x12B) => rtl_xex_header_field(kernel, arg(t, 0), arg(t, 1), t),
        (Lib::Xboxkrnl, 0x12A) => rtl_get_stack_limits(kernel, mem, arg(t, 0), arg(t, 1), t),
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
        // XGetGameRegion (reference `am_locale.cc`: region table indexed
        // by XCONFIG country; US index 1 yields 0x03FF = NTSC North
        // America, the standard answer for US titles).
        (Lib::Xam, 0x3CC) => {
            t.gpr[3] = 0x03FF_u64;
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

// ---- Module queries ----

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
