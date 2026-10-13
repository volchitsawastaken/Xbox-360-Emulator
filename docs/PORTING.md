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

## Next candidates

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
