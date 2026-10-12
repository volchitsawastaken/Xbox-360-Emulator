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
