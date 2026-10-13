# TODO board (x360-rs)

Statuses: done (verified), active (in progress), next (queued), later.
Terminal states only: impossible, done, or something rendering.

## Done (verified by tests and/or retail runs)

- [x] Workspace (12 crates), PPC interpreter core, 512MB mirrored memory
- [x] XEX1/XEX2 header model, Basic decompression, PE section parsing
- [x] STFS reader (CON/PIRS/LIVE, SHA1-verified); Braid GOD extracts
- [x] XEX AES-128-CBC decrypt (public retail key); Braid default.xex
      decrypts to valid PE (entry 8236ef38, 8 sections, 517 imports)
- [x] Import-record parsing + ordinal maps (922 xboxkrnl + 1741 xam)
- [x] Flat XEX placement, thunk rewrite, variable backing stores
- [x] Kernel heap/stack/TLS/critical-sections/module facts
- [x] 30+ export shims (memory, strings, TLS, time, privilege, AV pack,
      system version, title id)
- [x] CPU: 64-bit GPRs, ld/ldu/std/stdu, cache ops, addic., carry chain,
      word mul/div, integer logicals
- [x] X-form/D-form operand-order fix (RS in RT field, dest in RA;
      reference `ppc_decode_data.h` RS()=RT() + disassembler `[RA],[RS]`);
      `neg` word; retail memmove prologue executes
- [x] FPU: FPR file, lfs/lfsu/lfd/lfdu/stfs/stfsu/stfd/stfdu,
      FP ALU (add/sub/mul/div/madd/msub/nmadd/nmsub, mdc+single),
      fmr/fneg/fabs/fnabs/frsp/fctiw/fctiwz/fsqrt/fres/frsqrte/fsel,
      fcmpu/fcmpo, stfiwx/lfiwax
- [x] Retail boots from entry through startup into game code
      (first import call + AV/version/title-id queries pass)
- [x] Retail Braid runs 2M guest steps fault-free (10 kernel imports
      served: TLS/crits/2x NtAllocate/privilege/AV pack/header-field);
      progress-floor gate in `retail_braid_steps`

## Active

- [ ] Heap-walk cycle at 8236C1B4 (2-cycle 840301D8<->840308D8, key
      r9=0x8353): find what built the cyclic links (steps ~40k) and
      whether a CPU op or shim value diverged; then rerun for next fault

## Next (retail-driven, in expected order)

- [ ] 64-bit mul/div (`mulhd`, `divd`), `mftb`, VMX128
- [ ] Kernel shims on demand (file I/O, video mode, content, threads)
- [ ] Commit + push; update PORTING.md / COMPATIBILITY.md

## Later roadmap

- [ ] LZX decompression, GPU draw/state + shaders, FP exception/FPSCR control
- [ ] ISO/GDFX/SVOD, audio, input, frontend per-game config
- [ ] Broader unstubbed OS (background track)
- [ ] Fully done emulator OR last verified retail step
