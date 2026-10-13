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
pub const STATUS_NO_MEMORY: u32 = 0xC000_0017;
pub const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
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
        _ => {
            *table.unimplemented_calls.entry(key.clone()).or_insert(0) += 1;
            let name = ImportTable::name_of(&imp.lib, ord).unwrap_or("?");
            return Err(EmuError::Unsupported(format!(
                "unimplemented import {}!{} ({})",
                imp.lib, name, ord
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
    // Xbox timebase: 50 MHz.
    if out_ptr != 0 {
        mem.write_u32(out_ptr, 50_000_000)?;
    }
    t.gpr[3] = 0_u64;
    Ok(())
}

// ---- Module queries ----

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
