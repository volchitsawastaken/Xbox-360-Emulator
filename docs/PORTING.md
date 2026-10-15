# Port Ledger

Scope: format data and facts only, ported from the read-only reference
tree (`xenia-ref`, Xenia-Canary, BSD-licensed) into this repo. No
reference code is reused; all parsing, decode, dispatch, and
translation logic here is original. The reference clone lives outside
this repo and is never compiled in. Each item below names the source
file, what was taken, where it lives here, what was deliberately left
out, and the license note. Workspace license: BSD-3-Clause.

## 1. XEX directory keys and entry model

- Source: `src/xenia/kernel/util/xex2_info.h`, `xex2_header_keys` enum
  (file header: BSD license, Copyright 2013 Ben Vanik).
- Taken (facts only): numeric directory key values —
  entry point `0x00010100`, image base `0x00010201`, original base
  `0x00010001`, default stack size `0x00020200`, execution info
  `0x00040006`, import libraries `0x000103FF`, system flags
  `0x00030000` — plus the 8-byte directory entry shape (key u32 BE,
  value-or-offset u32 BE) and the security-header image-size
  (+0x04) / load-address (+0x110) offsets as implemented.
- Lives here: `crates/loader/src/lib.rs` — `KEY_*` constants,
  `XexHeader` / `XexDir` / `XexDirData`, `parse_xex()`; attribution
  note in the module docs (top of file).
- NOT taken: decryption/decompression, page-descriptor mapping, PE
  section loading, import/TLS resolution, delta-patch handling (all
  reference-side logic in `src/xenia/cpu/xex_module.cc`). The loader
  stores validated raw `dirs` for later stages and rejects OOB data.
- License: reference is BSD (Ben Vanik / Xenia project); our parser
  is original code under the workspace BSD-3-Clause. Attribution is
  kept in the module docs.

## 2. PM4 Type-3 opcode table

- Source: `src/xenia/gpu/xenos.h`, `Type3Opcode` enum (spot-verified:
  `PM4_NOP = 0x10`, `PM4_DRAW_INDX = 0x22`, `PM4_DRAW_INDX_2 = 0x36`,
  `PM4_DRAW_INDX_BIN = 0x34`, `PM4_DRAW_INDX_2_BIN = 0x35`).
- Taken (facts only): opcode byte values, names, and one-line
  meanings (40-entry table plus the four draw opcodes in `is_draw`).
  The `OpcodeKind` buckets (Draw/State/Sync/Memory/Other) are our own
  grouping.
- Lives here: `crates/gpu/src/pm4.rs` — `lookup()`, `OpcodeInfo` /
  `OpcodeKind`, `is_draw()`; consumed for packet naming by
  `crates/gpu/src/lib.rs` (`dispatch()`) and
  `crates/gpu/src/bridge.rs` (`execute_buffer()`). Attribution note
  in the module docs (top of file).
- NOT taken: header bit-framing, per-opcode payload semantics,
  draw/state translation, shader handling. `dispatch()` reports every
  Type-3 packet as a pending-M5 error; draw count stays 0.
- License: reference is BSD (Ben Vanik / Xenia project); our table
  module and all logic are original under the workspace
  BSD-3-Clause. Attribution is kept in the module docs.

## 3. GPU register-address table

- Source: `src/xenia/gpu/register_table.inc` (`XE_GPU_REGISTER` dword
  indices; address rule byte = index * 4, spot-verified:
  `RB_SURFACE_INFO 0x2000 -> 0x8000`,
  `SQ_PROGRAM_CNTL 0x2180 -> 0x8600`,
  `VGT_DRAW_INITIATOR 0x21FC -> 0x87F0`,
  `RB_COPY_CONTROL 0x2318 -> 0x8C60`,
  `RB_COLOR_CLEAR 0x231E -> 0x8C78`) with one-line meanings following
  the field descriptions in `src/xenia/gpu/registers.h`.
- Taken (facts only): curated 37-entry table of byte addresses,
  names, and one-line meanings. The `RegGroup` buckets are our own
  grouping.
- Lives here: `crates/gpu/src/regs.rs` — `TABLE`, `lookup()`,
  `is_known()` (declared `pub mod regs` in `crates/gpu/src/lib.rs`),
  covered by resolve/unknown/duplicate unit tests. Not yet consulted
  by `dispatch()` or the bridge, which still uses the `0x2000`
  harness clear-color convention.
- NOT taken: register bitfield structs and behavioral semantics in
  `registers.h`, and any state-application logic.
- License: reference is BSD (Ben Vanik / Xenia project); our table
  module is original under the workspace BSD-3-Clause. Attribution
  is kept in the module docs.

## 4. STFS container layout and block map

- Source: `src/xenia/vfs/devices/stfs_xbox.h` (volume descriptor,
  hash-entry, directory-entry structs) + `stfs_container_device.{h,cc}`
  (block-to-offset map, hash-block-number walk, chain following).
- Taken (facts only): magic `CON `/`PIRS`/`LIVE` at 0x00, header size
  u32be at 0x340, descriptor at 0x379 (0x24 bytes, read-only flag bit 0,
  table count u16be, table block u24le, total blocks u32be), volume
  type u32be at 0x3A9 (0 = STFS), 0x1000-byte blocks with 170-entry
  hash tables (sha1 + info u32be, low 24 = next, `0xFFFFFF` = end),
  level spans {170, 28900, 4913000}, 64-entry directory blocks of
  0x40 bytes. Dual-backing + SVOD deliberately left out.
- Lives here: `crates/filesystem/src/stfs.rs` — `StfsImage::open`,
  `list_files`, `read_file` (SHA1-verified per block); `identify()`
  in `lib.rs` now sniffs the three magics. Provenance note in the
  module docs.
- NOT taken: write path, journaling, device mounting, SVOD layout.
- License: reference is BSD (Ben Vanik / Xenia project); our reader
  is original under the workspace BSD-3-Clause. Attribution is kept
  in the module docs.

## 5. XEX AES session-key unwrap + CBC stream decrypt

- Source: `src/xenia/cpu/xex_module.cc` (public `xe_xex2_retail_key`,
  `aes_decrypt_buffer` zero-IV CBC with cross-call chaining,
  `ReadImageBasicCompressed` decrypt-then-decompress order, wrapped
  image key at security +0x150).
- Taken (facts only): the 16-byte retail key constant, the CBC chaining
  rule (decrypt block, XOR previous ciphertext, IV starts zero, state
  carries across blocks), and the Normal+Basic pipeline order.
- Lives here: `crates/loader/src/image.rs` — `RETAIL_KEY`,
  `Cbc::decrypt_into`, `unwrap_session_key`, `loadable_image`
  Normal+Basic arm; security key plumbed via `XexInfo::aes_key` in
  `crates/loader/src/lib.rs`. Verified against an OpenSSL-produced
  vector plus retail Braid bytes. Attribution note in the module docs.
- NOT taken: LZX decompression, delta patching, devkit keys.
- License: reference is BSD (Ben Vanik / Xenia project); our crypto
  glue is original under the workspace BSD-3-Clause (AES primitive
  itself is the `aes` crate). Attribution is kept in the module docs.

## 6. PPC RS-in-RT/dest-in-RA layouts + FP conversion facts

- Source: `src/xenia/cpu/ppc/ppc_decode_data.h` (`RS() const {
  return RT(); }` across FormatX/FormatD) +
  `ppc_opcode_disasm_gen.cc` (`andi.`/`ori`/`oris`/`or`/`extsw` print
  `[RA],[RS]`), `ppc_emit_fpu.cc` (`InstrEmit_fctiwxx_` NaN-to-
  `0x80000000` + sign-extend-then-Cast bit storage,
  `InstrEmit_negx` CA-untouched negate).
- Taken (facts only): RS lives in the RT field and the destination
  in RA for X-form logicals/shifts/extends AND D-form logicals
  (ori/oris/xori/andi./andis.); `neg` XO 104; fctiw NaN/out-of-range
  yields `0x80000000`; single-precision primaries round via f32.
- Lives here: `crates/cpu/src/decode.rs` (corrected arms, primaries
  59/63 FP XOs, stfiwx 659 / lfiwax 769) and `crates/cpu/src/exec.rs`
  (FP ALU with fused `mul_add`, ties-even dynamic rounding, CR1=0
  documented); retail Braid memmove + FP init execute.
- NOT taken: FPSCR exception modeling, rounding-mode switching,
  VMX128.
- License: reference is BSD (Ben Vanik / Xenia project); our decode
  and logic are original under the workspace BSD-3-Clause.
  Attribution is kept in the module docs.

## 7. Kernel threading/sync/XConfig facts

- Source: `src/xenia/kernel/xboxkrnl/xboxkrnl_threading.cc`
  (`ExCreateThread` stack default/round/min, `ReturnKThreadPtr`
  0x80, `NtCreateSemaphore/Event/Mutant/Timer` signatures,
  `KeSetAffinityThread` prev-via-pointer + affinity!=0 check,
  `XThread::SetPriority` clamp-at-0, `NtYieldExecution` returns 0),
  `xthread.h` (`X_KTHREAD` field offsets, `X_KSEMAPHORE` 0x14,
  `X_KMUTANT` 0x20, `X_KTIMER`, `KTHREAD_STATE_*`),
  `xobject.h` (`X_OBJECT_TYPES` bytes, `X_DISPATCH_HEADER` 0x10),
  `xevent.cc` (manual=notification/0, auto=synchronization/1),
  `xbox.h` (NTSTATUS values), `xboxkrnl_ob.cc`
  (`ObReferenceObjectByHandle` zeroes out_ptr first),
  `xam/am_locale.cc` (`XGetGameRegion` country table, US index 1 =
  0x03FF), `xconfig.h` + `xconfig.cc` (`SetDefaults`: language 1,
  country 103, audio 0x00010001, retail 0x40, video 0,
  av_region 0x00400100; field sizes), `xboxkrnl_xconfig.cc`
  (entry semantics incl. BUFFER_TOO_SMALL + INVALID_PARAMETER_3),
  `xam_net.cc` (`X_WSADATA` 0x190 layout).
- Taken (facts only): struct sizes/offsets, enum/flag/NTSTATUS
  numerics, function signatures and status behavior, default values.
- Lives here: `crates/kernel/src/lib.rs` (NT object tracking +
  guest backing structs) and `crates/kernel/src/dispatch.rs`
  (shim handlers + unit tests); retail Braid boots 8M steps
  through thread/sync/locale init into file I/O.
- NOT taken: thread scheduling (created threads unscheduled),
  blocking waits, named-object matching, `X_OBJECT_TYPE` structs
  (type check in ObReference skipped, documented), APCs, timers
  firing, real sockets.
- License: reference is BSD (Ben Vanik / Xenia project); our
  tracking and logic are original under the workspace
  BSD-3-Clause. Attribution is kept in the module docs.

## 8. File I/O / video-init / error-table / MMIO / A-form facts

- Source: `src/xenia/kernel/xboxkrnl/xboxkrnl_io.cc`
  (`NtCreateFile` root handling, `CreateOptions`,
  `IsValidPath` call sites), `kernel.h` (`X_OBJECT_ATTRIBUTES`,
  `X_ANSI_STRING`), `vfs/entry.h` (`FileDisposition`,
  `FileAction`), `vfs/virtual_file_system.cc` (`OpenFile` decision
  table, case-insensitive child lookup), `xfile.cc` (`Read`
  position/EOF semantics), `xbox.h` (NTSTATUS values),
  `src/xenia/kernel/xboxkrnl/xboxkrnl_io_info.cc`
  (`GetQueryFileInfoMinimumLength` classes, query switch arms for
  Internal/Position/Alignment/Sector/XCTD/NetworkOpen, default arm
  INVALID_PARAMETER with zero output),
  `src/xenia/kernel/xboxkrnl/xboxkrnl_video.cc`
  (`VdSetDisplayMode` 0, `VdRetrainEDRAM(Worker)` 0,
  `VdIsHSIOTrainingSucceeded` TRUE, `kernel_display_gamma_type` 2 /
  `kernel_display_gamma_power` 2.22222233, `VdQueryVideoMode`
  1280x720 HDMI + NTSCM defaults, AsicID),
  `src/xenia/kernel/xboxkrnl/xboxkrnl_error.cc`
  (`xeRtlNtStatusToDosError` algorithm + `error_table_0xC0000001` /
  `error_table_0x00000103` entries, 317 fallback),
  `src/xenia/memory.cc` (MMIO `0x7FC80000-0x7FFFFFFF`, GPU
  writeback `0x7F000000-0x7FC7FFFF`),
  `src/xenia/cpu/ppc/ppc_opcode_table_gen.cc` (`ldx` 21, `ldux`
  53, `stdx` 149, `stdux` 181) and the A-form layout (5-bit XO
  under the FRC field; `fmuls` XO 25).
- Taken (facts only): path/device/disposition/action numerics,
  info-class minimums and layout offsets, video default values,
  mapped NTSTATUS-to-DOS pairs, address-window bounds, XO numbers.
- Lives here: `crates/kernel/src/fs.rs` + `crates/filesystem/src/stfs_fs.rs`
  (path model + STFS backend), `crates/kernel/src/dispatch.rs`
  (file/video/error shims + unit tests),
  `crates/memory/src/lib.rs` (MMIO/writeback windows),
  `crates/cpu/src/decode.rs` (dword-indexed + A-form XOs).
- Source: `src/xenia/cpu/ppc/ppc_emit_alu.cc` (`InstrEmit_addx/
  addcx/addex/addi/addic/addicx/addis/addmex/addzex/negx/subfx/
  subfcx/andx/andcx/andix/orx/nandx/extsbx/extshx/extswx/slwx`:
  full-width GPR arithmetic/logical/extend ops; D-form logicals
  and word shifts/rotates stay 32-bit; plain `add`/`subf` record
  no CA).
- Taken (facts only): 64-bit op widths, CA/OV/CR0 recording rules.
- Lives here: `crates/cpu/src/exec.rs` (widened arms + unit tests).
- NOT taken: directory enumeration order guarantees, file
  timestamps, unmapped error-table ranges (317 fallback, documented),
  GPU register behavior behind MMIO (backing bytes only).
- License: reference is BSD (Ben Vanik / Xenia project); our
  tracking and logic are original under the workspace
  BSD-3-Clause. Attribution is kept in the module docs.

## 9. VMX128 integer layouts, 64-bit compares, locks/locales/tracing facts

- Source: `src/xenia/cpu/ppc/ppc_decode_data.h`
  (`FormatVX` VA-is-bits-16-20 immediate, `FormatVX128_1` 7-bit
  VD, `FormatVX128_2` VD/VA/VB/VC split, `FormatXS` SH5-in-bit-1
  count, `FormatVA` VC-in-bits-6-10),
  `src/xenia/cpu/ppc/ppc_opcode_table_gen.cc` (kVX
  `vspltisb` 0x30C / `vspltish` 0x34C / `vspltisw` 0x38C /
  `vslb` 0x104 / `vor` 0x484 / `vspltb` 0x20C / `vperm` 0x2B /
  `vsel` 0x2A; kVX128_1 `lvx`/`stvx`/`lvlx`/`lvrx`/`stvlx`/
  `stvrx`; kVX128_2 `vperm128` base; XO `lvsl` 6 / `lvsr` 38 /
  `lvebx` 7 / `lvehx` 39 / `lvewx` 71 / `lvx` 103 / `stvebx`
  135 / `stvehx` 167 / `stvewx` 199 / `stvx` 231 / `lvlx` 519 /
  `lvrx` 551 / `stvlx` 647 / `stvrx` 679 / `sradix` 826),
  `src/xenia/cpu/ppc/ppc_emit_altivec.cc`
  (`InstrEmit_vspltisb/vspltish/vspltb/vslb/vor/lvx_/stvx_/
  lvsl_/lvsr_/vperm_/vsel_`; `lvebx/lvehx/lvewx` equal `lvx`;
  `stvlx` writes bytes `offset..15`, `stvrx` bytes `0..offset-1`
  with `eb==0` a no-op; `lvrx` zeroes at `eb==0`),
  `src/xenia/cpu/hir/hir_builder.cc` + `backend/*/a64_seq_vector.cc`
  / `x64_seq_memory.cc` (LVL/LVR/STVL/STVR TBL blends),
  `src/xenia/cpu/ppc/ppc_emit_alu.cc` (`InstrEmit_cmp/cmpi/
  cmpl/cmpli` L=0 32-bit vs L=1 64-bit with EXTS/zero-extended
  immediates; `InstrEmit_sradix` n==0 copy + CA rule),
  `src/xenia/kernel/xboxkrnl/xboxkrnl_threading.cc`
  (`X_ERWLOCK` 0x38 layout, init/acquire/try/release counter
  moves; `XDPC` layout + `Initialize`; `KeInitializeEvent` zero +
  type/signal, `KeInitializeSemaphore` type/count/limit),
  `src/xenia/kernel/xobject.h` (`X_OBJECT_TYPES`
  sync-event 1 / semaphore 5), `src/xenia/kernel/xam/am_locale.cc`
  (`xeGetLanguage` English fallback, `xeXamGetLocale` US 36,
  `XamGetOnlineLanguageAndCountry` byte writes, `XLanguage`
  English 1), `src/xenia/kernel/xam/am_info.cc`
  (`staging_mode` 0, dash-context store + `0x8000000C`
  broadcast, backstack empty-drain, launch-data NOT_FOUND),
  `src/xenia/kernel/xam/am_video.cc` (`XGetVideoMode` =
  `VdQueryVideoMode`), `src/xenia/xbox.h`
  (`kXNotificationSystemDashContextChanged` 0x8000000C),
  `src/xenia/kernel/xboxkrnl/xboxkrnl_hal.cc` (`avpack` 8),
  `src/xenia/kernel/xboxkrnl/xboxkrnl_usbcam.cc`
  (`CamNotConnected` 0), `src/xenia/kernel/xboxkrnl/
  xboxkrnl_crypt.cc` (`XeCryptRandom` 0xFD fill),
  `src/xenia/kernel/xboxkrnl/xboxkrnl_io.cc`
  (`FscGet/SetCacheElementCount` 0), `src/xenia/kernel/xboxkrnl/
  xboxkrnl_ob.cc` (`ObCreateSymbolicLink` register + qualifier
  strip), `src/xenia/kernel/xam/am_ui.cc`
  (`XamPackageManagerGetExperienceMode` usage notes),
  `src/xenia/kernel/xam/xam_table.inc` + `xboxkrnl_table.inc`
  (ordinal confirmations).
- Taken (facts only): register-field maps, XO numbers, zero-fill /
  no-op edges, 64-bit compare widths, lock/counter layouts,
  locale/mode constants, offline answers.
- Lives here: `crates/cpu/src/decode.rs` (VMX128 + `Sradix`
  variants), `crates/cpu/src/regs.rs` (128-entry VR file),
  `crates/cpu/src/exec.rs` (arms + unit tests),
  `crates/kernel/src/lib.rs` (`dash_context`, `launch_data`,
  `symlinks`, `vd_studio_rgb`), `crates/kernel/src/dispatch.rs`
  (shims + unit tests), `crates/filesystem/src/hostdir_fs.rs`.
- NOT taken: VMX128 128-bit FP arithmetic, blocking lock waits
  (explicit Unsupported), download/storage backends, ETX consumers.
- License: reference is BSD (Ben Vanik / Xenia project); our
  tracking and logic are original under the workspace
  BSD-3-Clause. Attribution is kept in the module docs.

## 10. GPU ring pump + PM4 memory/register packet facts

- Source: `src/xenia/gpu/command_processor.cc`
  (`InitializeRingBuffer` zero of `1 << (size_log2 + 3)`,
  `EnableReadPointerWriteBack`, worker consume-`[read, write)` +
  writeback publish, `0xBAADF00D` empty sentinel),
  `src/xenia/gpu/graphics_system.cc` (`WriteRegister`: `r =
  (addr & 0xFFFF) / 4`, `CP_RB_WPTR 0x01C5` kick),
  `src/xenia/gpu/xenos.h` (type-3 `opcode/count` framing,
  `GpuSwap`/`Endian` table, opcode numbers),
  `src/xenia/gpu/pm4_command_processor_implement.h`
  (`ExecutePacket` skips, type-0 `base/count + 1` + bit-15
  write-one, type-1 pairs, IB `[ptr, len & 0xFFFFF]` in dwords,
  MEM_WRITE/EVENT_WRITE_SHD/EXT/REG_RMW/REG_TO_MEM/WAIT/COND/
  INTERRUPT payload layouts, `MatchValueAndRef`),
  `src/xenia/gpu/register_table.inc` (`WRITEBACK_START 0x0A04`,
  `WRITEBACK_SIZE 0x0A05`, `VGT_EVENT_INITIATOR 0x21F9`,
  `RB_SAMPLE_COUNT_ADDR 0x2325`),
  `src/xenia/gpu/graphics_system.cc` (`SetInterruptCallback`,
  `DispatchInterruptCallback(source=1, cpu=bit)`),
  `src/xenia/kernel/kernel_state.cc` (`EmulateCPInterruptDPC`:
  early-return when null, args `{source, data}`),
  `src/xenia/cpu/processor.cc` (`Execute`: stack pad `64+112`,
  LR sentinel `0xBCBCBCBC`, args in r3+).
- Taken (facts only): register index + framing/field maps, zero
  size, swap table, match function, writeback remap rule.
- Lives here: `crates/kernel/src/gpu.rs` (executor + unit tests),
  `crates/kernel/src/lib.rs` (`pump_gpu`, `vd_regs`,
  `vd_irq_pending` queue, `vd_callback_active`, `vd_delivered`),
  `crates/kernel/src/boot.rs` (per-step pump + sentinel hijack
  delivery/return), `crates/kernel/src/dispatch.rs` (ring-zero shim
  + test).
- NOT taken: draw/state packet semantics (length-skipped), shader
  upload, EDRAM/resolve, DPC IRQL impersonation (no guest KPCR yet;
  delivery restores full state instead of clobbering volatiles).
- License: reference is BSD (Ben Vanik / Xenia project); our
  tracking and logic are original under the workspace
  BSD-3-Clause. Attribution is kept in the module docs.

## 11. Thread startup, KeWait/KeResetEvent, messagebox facts

- Source: `src/xenia/kernel/xthread.cc` (`XThread::Execute`:
  raw threads start at `start_address` with `start_context` as the
  single arg, return value in r3 becomes the exit code),
  `src/xenia/kernel/xboxkrnl/xboxkrnl_threading.cc`
  (`NtWaitForSingleObjectEx`/`KeWaitForSingleObject_entry`:
  `(handle_or_ptr, mode, alertable, timeout_ptr)`, NULL timeout =
  infinite, kBlocking; `KeResetEvent_entry`: clear + return
  previous state),
  `src/xenia/kernel/kernel.h` (`MESSAGEBOX_RESULT`: `ButtonPressed`
  u32be at +0, 8 bytes),
  `src/xenia/kernel/xam/am_ui.cc` (`XamShowMessageBoxUi`: raw
  UTF-16 title/text/buttons, empty list falls back to "OK",
  headless auto-picks the focused button + SUCCESS),
  `src/xenia/kernel/xevent.h` (`X_KEVENT` = 0x10-byte
  `X_DISPATCH_HEADER`: type byte 0 = Notification/manual, 1 =
  Synchronization/auto, signal at +4),
  `src/xenia/kernel/xboxkrnl/xboxkrnl_threading.cc`
  (`KeInitializeEvent_entry`: zero + set type/signal;
  `xeKeSetEvent`/`KeSetEvent_entry`, `KePulseEvent_entry`,
  `KeResetEvent_entry`: return previous state).
- Taken (facts only): startup arg convention, wait signatures +
  NULL semantics, reset return, result layout, headless rule, event
  header layout + init/set/pulse/reset returns.
- Lives here: `crates/kernel/src/boot.rs` (spawn drain + round
  robin), `crates/kernel/src/lib.rs` (slot assignment, `Blocked`,
  `ke_events` + adoption), `crates/kernel/src/dispatch.rs`
  (`KeWaitForSingleObject`, `KeResetEvent`, `KeSetEvent`,
  `KePulseEvent`, `KeInitializeEvent`, `XamShowMessageBoxUI(Ex)` +
  unit tests), `crates/common/src/lib.rs` (`EmuError::Blocked`).
- NOT taken: time-based finite waits (immediate TIMEOUT),
  overlapped-async UI completion (sync completion), APC delivery.
  (Interrupt-callback delivery is now implemented — see §10.)
- License: reference is BSD (Ben Vanik / Xenia project); our
  tracking and logic are original under the workspace
  BSD-3-Clause. Attribution is kept in the module docs.

## 12. VMX128 classic FP arithmetic facts

- Source: `src/xenia/cpu/ppc/ppc_opcode_table_gen.cc`
  (`vaddfp 0x1000000A`, `vsubfp 0x1000004A`, `vmaxfp 0x1000040A`,
  `vminfp 0x1000044A`, all kVX; `vaddfp128 0x14000010`,
  `vsubfp128 0x14000050`, `vmulfp128 0x14000090`, kVX128),
  `src/xenia/cpu/ppc/ppc_decode_data.h` (`FormatVX128` highs),
  `src/xenia/cpu/ppc/ppc_emit_altivec.cc` (`InstrEmit_vaddfp_` /
  `vsubfp_` / `vmaxfp_` / `vminfp_` / `vmulfp128`: 4 x f32 lane ops).
- Taken (facts only): XO numbers, `FormatVX128` high-field map,
  lane width/count, max/min/mul shape.
- Lives here: `crates/cpu/src/decode.rs` (kVX XO + kVX128 masked
  arms) + `crates/cpu/src/exec.rs` (BE f32 lane ops + unit tests).
- NOT taken: fused FP (madd/msum/nmadd/nmsub), FP compares/converts
  (cmpb/cmpeq/cmpge/cmpgt, csxwfp/cuxwfp, ref/rsqrte/expte/loge),
  FP exception/FPSCR control.
- License: reference is BSD (Ben Vanik / Xenia project); our
  tracking and logic are original under the workspace
  BSD-3-Clause. Attribution is kept in the module docs.

Concrete, data-only port targets. Each names the reference path and
the file it would land in.

1. Wire `regs::lookup` into Type-0 dispatch and the bridge —
   reference: item 3 above plus field semantics in
   `src/xenia/gpu/registers.h` — lands in
   `crates/gpu/src/lib.rs` (`dispatch()`) and
   `crates/gpu/src/bridge.rs` (retire the `0x2000` harness register
   in favor of `RB_COLOR_CLEAR 0x8C78`). Advances the
   "Host clear from guest state" matrix row past its harness
   convention.
2. XEX section/import/TLS payload layouts — reference:
   `src/xenia/kernel/util/xex2_info.h` (`PESection` struct; keys
   `TLS_INFO 0x00020104`, `RESOURCE_INFO 0x000002FF`,
   `FILE_FORMAT_INFO 0x000003FF` in the same enum) — lands in
   `crates/loader/src/lib.rs` (interpret `XexDirData::AtOffset`
   payloads). Advances the "Relocations/imports/TLS" matrix row.
3. XEX page-descriptor mapping — reference:
   `src/xenia/cpu/xex_module.cc` (page-descriptor loop over
   `page_descriptor_count` with `xex2_page_descriptor`) — lands in
   `crates/loader/src/lib.rs` plus `crates/memory/src/lib.rs`
   (region mapping).
4. XEX PE section loading — reference:
   `src/xenia/cpu/xex_module.cc` (`NumberOfSections` loop,
   `PointerToRawData` / `VirtualAddress` placement) — lands in
   `crates/loader/src/lib.rs` (per-section placement through
   `load_bytes_to_guest`).
5. Per-opcode Type-3 payload field layouts — reference:
   `src/xenia/gpu/packet_disassembler.cc` (`DisasmPacketType3`:
   opcode-bits and count-bits extraction plus the per-opcode
   switch) — lands in `crates/gpu/src/lib.rs` (`dispatch()`).
   Advances the "Draw/state/texture/RT packets" matrix row.
6. PPC decode-table extension (FP unit plus remaining XO forms) —
   reference: `src/xenia/cpu/ppc/` (`ppc_decode_data.h`,
   `ppc_instr.h`, `ppc_opcode.h`, `ppc_opcode_info.h`) — lands in
   `crates/cpu/src/decode.rs` (new `Decoded` variants) and
   `crates/cpu/src/exec.rs` (execution arms). Advances the
   "FP unit" matrix row.

## Could not verify (not guessed)

- The low-byte inline-vs-offset directory storage rule as a line in
  `xex2_info.h`: it is implemented in `parse_xex()` but I did not
  pin it to a reference line, so its provenance stays unattributed.
- Execution-info struct field offsets (title_id at +0x0C) as a
  reference line: implemented in the loader, not pinned to a line I
  read.
- Full 40-entry PM4 table against the reference enum (5 values
  spot-checked); likewise the 29-opcode "reference set" asserted in
  the `pm4.rs` test against the `packet_disassembler.cc` switch
  (switch existence verified, not every arm).
- `regs.rs` one-line meanings against the `registers.h` field
  comments (5 of 37 addresses verified arithmetically).
