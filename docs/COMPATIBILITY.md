# Compatibility Matrix

Statuses: `verified` (tested, evidence), `partial` (some paths work),
`unsupported` (explicit error), `not-started`.

## CPU (Xenon PPC)

| Area | Status | Notes |
|---|---|---|
| Integer ALU (addi, addis, ori, oris, xori, andi, extsh/extsb, shifts) | partial | Covered by unit vectors; OE/OV/SO honored for add/subf; X-form + D-form logicals use RS-in-RT/dest-in-RA layout (reference RS()=RT()); `neg` word with OE on 0x80000000 |
| Branches (b, bc, bclr + LK) | partial | CR/BI/BO honored, LK writes LR; bcctr does not decrement CTR |
| bcctr | partial | Target from CTR, no decrement; tested |
| Loads/stores (lwz/stw/lbz/stb/lhz/sth/lmw/stmw/multiple) | partial | Alignment + bounds checked (u32/u16/u8); u64 permissive on 4-aligned (retail `std` to 4-aligned tolerated like reference memory); EXEC required for fetch |
| CR/XER/LR/CTR moves (mfcr/mtcr, mflr/mtlr, mfctr/mtctr, mfxer) | partial | LR/CTR only; other SPRs explicit Unsupported |
| lwarx/stwcx. reservations | partial | Single-thread correct + CR EQ; SMP invalidation pending |
| sync/lwsync/isync/eieio | partial | Barriers as scheduler fences for now |
| VMX128 vector ops | unsupported | Tracked per-opcode, required for retail |
| FP unit | partial | FPR file + D-form lfs/lfd/stfs/stfd (plain+update); double+single ALU (add/sub/mul/div/madd/msub/nmadd/nmsub, fused mul_add), fmr/fneg/fabs/fnabs/frsp/fctiw(fctiwz)/fsqrt/fres/frsqrte/fsel, fcmpu/fcmpo to CR, stfiwx/lfiwax; FPSCR exceptions unmodeled (CR1=0), RN assumed nearest-even; tested |
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
| Threads/events/mutexes/sems | partial | create_thread/event/set/wait with queued waiters; blocking wait pending M6 |
| Syscalls | partial | 0=time, 2=putc console tested; others explicit UnimplementedSyscall; 1=exit handled by boot runner |
| Boot | partial | Demo guest (putc "HI" + exit 0) verified end-to-end via `run_until_exit`; retail Braid runs 2M steps fault-free from entry (10 imports served) with progress-floor gate; currently inside heap-walk init at 8236C1B4 |
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
| Debugger disasm/regs/mem/breakpoints | partial | Backed by real CPU state; shown in UI (disasm@pc, regs, GPU stats) |
| Compat indicators | partial | Labels say loads/not-verified; see matrix, no playable claims |
