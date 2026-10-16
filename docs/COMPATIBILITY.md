# Compatibility Matrix

Statuses: `verified` (tested, evidence), `partial` (some paths work),
`unsupported` (explicit error), `not-started`.

## CPU (Xenon PPC)

| Area | Status | Notes |
|---|---|---|
| Integer ALU (addi, addis, ori, oris, xori, andi, extsh/extsb, shifts) | partial | Full 64-bit add/sub family per reference (`addi`/`addis`/`addic`/`subfic`/`mulli`/`add`/`subf`/`neg`/`addc`/`adde`/`addme`/`addze`/`subfc`/`subfe`/`subfme`/`subfze` with 64-bit CA/OV/CR0; plain add/subf record no CA); X-form logicals (`or`/`and`/`xor`/`nor`/`andc`/`orc`/`nand`/`eqv`) 64-bit; `extsh`/`extsb` sign-extend to 64; D-form logicals, word shifts, `cntlzw` stay 32-bit; OE/OV/SO honored; X-form + D-form logicals use RS-in-RT/dest-in-RA layout (reference RS()=RT()); tested |
| Branches (b, bc, bclr + LK) | partial | CR/BI/BO honored, LK writes LR; bcctr does not decrement CTR |
| bcctr | partial | Target from CTR, no decrement; tested |
| Loads/stores (lwz/stw/lbz/stb/lhz/sth/lmw/stmw/multiple) | partial | Alignment + bounds checked (u32/u16/u8); u64 permissive on 4-aligned (retail `std` to 4-aligned tolerated like reference memory); X-form dword-indexed `ldx`/`ldux`/`stdx`/`stdux` (XOs 21/53/149/181) with update forms; EXEC required for fetch; MMIO window `0x7FC80000` (3.5MB backing) + `0x7F000000` writeback window (12.5MB zeroed) per reference map, EXEC denied in both |
| CR/XER/LR/CTR moves (mfcr/mtcr, mflr/mtlr, mfctr/mtctr, mfxer) | partial | LR/CTR only; other SPRs explicit Unsupported |
| lwarx/stwcx. reservations | partial | Single-thread correct + CR EQ; SMP invalidation pending |
| sync/lwsync/isync/eieio | partial | Barriers as scheduler fences for now |
| VMX128 vector ops | partial | Integer subset + FP (`vaddfp`/`vsubfp`/`vmaxfp`/`vminfp` + `vaddfp128`/`vsubfp128`/`vmulfp128` + `vmaddfp`/`vnmsubfp` fused + `vrefp`/`vrsqrtefp` estimates + `vcmpeqfp`/`vcmpgefp`/`vcmpgtfp`/`vcmpbfp` masks+CR6, 4x f32, tested incl. high regs/specials/Rc); converts + remaining ops tracked per-opcode |
| FP unit | partial | FPR file + D-form lfs/lfd/stfs/stfd (plain+update); double+single ALU (add/sub/mul/div/madd/msub/nmadd/nmsub, fused mul_add), fmr/fneg/fabs/fnabs/frsp/fctiw(fctiwz)/fctid/fcfid/fsqrt/fres/frsqrte/fsel, fcmpu/fcmpo to CR, stfiwx/lfiwax; A-form decodes on the real 5-bit XO (nonzero FRC, e.g. retail `fmuls` 0xEC200732); `mftb` (50MHz wall clock), `td`/`tdi` traps, word+doubleword mul/div (`mullw`/`mulhw`/`divw`, `mulld`/`mulhd`/`divd`); FPSCR exceptions unmodeled (CR1=0), RN assumed nearest-even; tested |
| Exceptions (DSI/ISI/program/sc) | partial | Fault codes surfaced; sc traps with r0=syscall id convention |
| 6-thread scheduling | partial | Xenon round-robin wired in frontend; priorities pending M6 |

## GPU (Xenos)

| Area | Status | Notes |
|---|---|---|
| Packet decode (type0/2/3) | partial | Real ringbuffer copy via decode_packet; header-only reports truncation; type1 errors |
| Type0 state | partial | Register file applied and tested, including from guest RAM via bridge |
| Command bridge (guest RAM → dispatch) | partial | `execute_buffer` reads PM4 from guest memory; Type3 counted/skipped with stats; tested |
| Host clear from guest state | partial | Harness clear-color reg → `render_clear` readback; convention labeled, hardware mapping pending |
| Draw/state/texture/RT packets | unsupported | Type3 dispatch returns pending-M5, draws stays 0 |
| Shader translate | unsupported | Hash + cache tracked, explicit UnimplementedShader |
| eDRAM tile/resolve | not-started | |
| Validation triangle | partial | Headless wgpu offscreen render + readback (`Xenos::validate_triangle`), tested; not Xenos translation |

## Loader / Kernel

| Area | Status | Notes |
|---|---|---|
| XEX2 header/directory parse | partial | Real XEX1/XEX2 model: 8-byte entries, inline (low byte 00/01) vs offset data, entry/base/stack/title/TLS/static-lib/format-info keys, security load address + AES key (+0x150); OOB rejected; 26 retail headers verified; tests |
| Image body (Basic decompression + AES) | partial | None+Basic and Normal+Basic verified: Braid default.xex (6,041,600 bytes) decrypts (AES-128-CBC, public retail key unwraps session key) + decompresses to PE with 8 sections, entry 0x8236EF38 covered, 517 imports; LZX stays explicit Unsupported; tests |
| Relocations/imports/TLS | partial | Import library names/ids/versions/counts parsed (Braid: 517 across libs); record patching + TLS resolution pending — first retail boot blocker |
| ISO/GDFX/STFS/extracted dir | partial | STFS read-only single-backing: CON/PIRS/LIVE magic, volume descriptor, hash-table block map, SHA1-verify per block, dir list + file extract; Braid GOD lists 15 entries, default.xex extracts byte-exact (XEX2 verified); dual-backing + SVOD explicit Unsupported |
| Threads/events/mutexes/sems | partial | NT sync objects with real guest backing structs (event/semaphore/mutant/timer create + release/set/clear/pulse/wait-single/wait-multiple, reference NTSTATUS, guest mirroring); ExCreateThread (real stacks + X_KTHREAD, Xenon slot = thread_id, exhaustion explicit) + cooperative round-robin scheduler (spawn drain, suspend counts, clean worker-return exits, Blocked rewind-retry) + resume/suspend/terminate/yield Ke* ptr APIs incl. KeWaitForSingleObject/KeResetEvent/KeSetEvent/KePulseEvent/KeInitializeEvent (game-allocated in-place adoption) + ObReference/ObLookupThreadByThreadId + KeEnter/LeaveCriticalRegion nesting; critsec free no longer collides with thread 0; infinite waits block, finite poll stays immediate; XamShowMessageBoxUI(Ex) headless-picks focused button; retail workers run, signal, and contend |
| File I/O (NT path) | partial | NtCreateFile/NtOpenFile (OBJECT_ATTRIBUTES + ANSI normalize, disposition table, write-intent ACCESS_DENIED), NtReadFile (offset windows, IOSB, PENDING, EOF), NtClose, NtQueryInformationFile (Internal/Position/NetworkOpen), RtlNtStatusToDosError (reference table); read-only StfsFs + HostDirFs backends; ObCreateSymbolicLink table; Fsc{Get,Set}CacheElementCount=0; tested |
| Video init | partial | VdInitializeEngines record, VdSetDisplayMode=0, VdCallGraphicsNotificationRoutines=0, VdGetCurrentDisplayGamma (TV + 2.22222233), VdRetrainEDRAM(Worker)=0, VdIsHSIOTrainingSucceeded, VdQueryVideoMode/XGetVideoMode 1280x720, VdQueryVideoFlags=3, AsicID 0x11, VdSetStudioRGBMode recorded, MmGetPhysicalAddress, KiApcNormalRoutineNop, KeInitializeDpc; PM4 ring executor (type-0/1, IB, MEM_WRITE/GpuSwap, SHD/EXT, RMW/TO_MEM, WAIT/COND, INTERRUPT per-bit queue, IM_LOAD ucode store, INVALIDATE no-op, DRAW count-and-skip, EDRAM 10 MiB clear/resolve state, XE_SWAP present (resolve + vblank)) + boot-runner pump + interrupt-callback delivery (sentinel hijack, tested) + VdSwap 10-arg validation writing the 64-word ring sequence (fetch load + XE_SWAP + NOP fill) + VdInitializeScalerCommandBuffer NOP-fill; draw/state packets skip (no draw backend yet; present path covers solid-cleared surfaces end to end) |
| Syscalls | partial | 0=time, 2=putc console tested; others explicit UnimplementedSyscall; 1=exit handled by boot runner |
| XConfig/locale | partial | ExGetXConfigSetting (reference defaults: language/country/region/flags), XGetGameRegion 0x03FF, XGetAVPack/HalGetCurrentAVPack 8, XamGetLanguage=1, XamGetLocale=36, XamGetOnlineLanguageAndCountry (1/103); tested |
| Boot | partial | Demo guest (putc "HI" + exit 0) verified end-to-end via `run_until_exit`; retail Braid boots from entry through thread/sync/locale/file-I/O/video init (heap base 0x01000000; 26 imports: TLS/crits/alloc/privilege/AV/region/XConfig/sync/threads/file-I/O/video-init/RtlNtStatusToDosError); STFS-backed boot with all 4 workers live reaches main-thread graphics init: KeWait succeeds via worker signaling, KeResetEvent served, XamShowMessageBoxUI auto-picks (fatal-error dialog path served); frontier is back at the stale +16 `bctr` (0x67735C65) with +120 still virgin — worker starvation eliminated, interrupt delivery implemented but Braid's stream queues zero interrupts (not the trigger; next is draw backend / device state); gate green in `retail_braid_steps`. Dash boots from HostDirFs through 63 imports to a fully-decoded table walk at 0x921B86BC (table = object+896, bound 0x10002 from the flag word, each slot a struct pointer; slot 6 holds version-string bytes from a faithful 148B static copy; zero file I/O — table is static+import driven; root cause open, same count-vs-data class as Braid) |
| ISO/GDFX/STFS/extracted dir | partial | identify + default.xex resolve; STFS payload parsing partial (see Loader rows above); ISO/GDFX pending |

## Audio

| Area | Status | Notes |
|---|---|---|
| XMA decode | unsupported | Explicit error |
| Output | partial | Null sink works and tested; host returns explicit Unsupported (cpal not wired) |

## Network

| Area | Status | Notes |
|---|---|---|
| XSocket UDP bridge | partial | Loopback send/recv tested |
| System Link discovery | partial | UDP beacon send/recv tested between two instances on loopback; broadcast + NAT pending M8 |
| Custom lobby | partial | Endpoint configurable; health check explicit Unsupported when empty; no server claims |
| Official Live compat | unsupported | Not claimed, not attempted |

## Frontend / Debugger

| Area | Status | Notes |
|---|---|---|
| Library launch + per-game config | partial | scan_library reads real FS; identify errors surfaced per-entry; labels state untested/playable explicitly |
| Step execution | partial | Steps all 6 threads; syscall errors propagated to log/status; r0=id convention |
| Boot loading screen | partial | Staged parse→map→gpu→run with progress + per-stage detail, all stages real; failures shown with dismiss |
| Debugger disasm/regs/mem/breakpoints | partial | Backed by real CPU state; shown in UI (disasm@pc, regs, GPU stats); TraceBuffer carries per-thread attribution with a file sink (`write_trace_file`) used for fault dumps |
| Compat indicators | partial | Labels say loads/not-verified; see matrix, no playable claims |
