# x360-rs

Modular Xbox 360 emulator written in Rust.

Windows-first, cross-platform by design. Safe Rust by default, `unsafe`
isolated and documented where required.

## Layout

- `crates/common` — errors, config, logging
- `crates/memory` — 512 MB unified memory, regions, permissions
- `crates/cpu` — Xenon PowerPC interpreter + VMX128, JIT-ready traits
- `crates/loader` — XEX parsing and validation
- `crates/gpu` — Xenos command processor, shader/resource tracking, wgpu backend
- `crates/audio` — XMA tracking and output backends
- `crates/filesystem` — ISO / STFS / extracted directory handling
- `crates/kernel` — threads, sync, syscalls, XAM services
- `crates/network` — XNet sockets, System Link LAN, custom lobby client
- `crates/debugger` — disassembly, breakpoints, tracing
- `crates/frontend` — desktop app, library, settings, debugger views
- `crates/emutests` — integration and regression tests

## Status

Milestone-based. See `docs/DESIGN.md` and `docs/COMPATIBILITY.md`.
No subsystem is marked complete without tests and measured behavior.
Unsupported paths return explicit errors and are logged.

## Build

```
cargo build
cargo test
cargo run -p x360-frontend
```

## Networking

Local System Link and custom lobby servers only. No official
service compatibility is claimed. Server endpoint is configurable.
No credentials are hardcoded.
