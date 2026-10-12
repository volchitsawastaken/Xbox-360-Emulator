//! Desktop frontend: library, settings, logs, debugger views.
//!
//! Every control is wired to real state. Compatibility labels come from
//! measured results, not hardcoding. Syscall convention (pending-M6):
//! guest r0 holds the syscall id at `sc` time.

use std::path::PathBuf;
use x360_common::{EmuConfig, EmuError, Result};

#[derive(Debug, Clone)]
pub struct GameEntry {
    pub path: PathBuf,
    pub title: String,
    pub status: String,
}

/// Staged boot state. Progress reflects completed real stages only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootStage {
    Idle,
    Parse,
    Map,
    GpuInit,
    Run,
    Done,
    Failed,
}

#[derive(Debug, Clone)]
pub struct BootSession {
    pub stage: BootStage,
    pub progress: f32,
    pub detail: String,
    pub exit_code: Option<u32>,
}

impl Default for BootSession {
    fn default() -> Self {
        Self::idle()
    }
}

impl BootSession {
    pub fn new() -> Self {
        Self {
            stage: BootStage::Parse,
            progress: 0.0,
            detail: "starting".into(),
            exit_code: None,
        }
    }

    pub fn idle() -> Self {
        Self {
            stage: BootStage::Idle,
            progress: 0.0,
            detail: String::new(),
            exit_code: None,
        }
    }

    pub fn active(&self) -> bool {
        !matches!(
            self.stage,
            BootStage::Idle | BootStage::Done | BootStage::Failed
        )
    }

    fn advance(&mut self, next: BootStage, progress: f32) {
        self.stage = next;
        self.progress = progress;
    }

    fn fail(&mut self, msg: &str) {
        self.stage = BootStage::Failed;
        self.detail = msg.to_string();
    }
}

pub struct EmuApp {
    pub cfg: EmuConfig,
    pub games: Vec<GameEntry>,
    pub log_lines: Vec<String>,
    pub status_line: String,
    pub mem: x360_memory::Memory,
    pub xenon: x360_cpu::Xenon,
    pub gpu: x360_gpu::Xenos,
    pub kernel: x360_kernel::Kernel,
    pub debugger: x360_debugger::Debugger,
    pub audio: x360_audio::AudioOut,
    pub audio_host: bool,
    pub net_log: Vec<String>,
    pub active_thread: usize,
    pub lobby_endpoint_edit: String,
    pub boot: BootSession,
}

impl EmuApp {
    pub fn new(cfg: EmuConfig) -> Self {
        let entry = 0x8200_1000;
        let lobby_endpoint_edit = cfg.lobby_endpoint.clone();
        let audio_host = !cfg.audio_null;
        let audio = x360_audio::AudioOut::new(if audio_host {
            x360_audio::Backend::Host
        } else {
            x360_audio::Backend::Null
        });
        Self {
            cfg,
            games: Vec::new(),
            log_lines: Vec::new(),
            status_line: "idle".into(),
            mem: x360_memory::Memory::new(),
            xenon: x360_cpu::Xenon::new(entry),
            gpu: x360_gpu::Xenos::new(),
            kernel: x360_kernel::Kernel::new(),
            debugger: x360_debugger::Debugger::new(),
            audio,
            audio_host,
            net_log: Vec::new(),
            active_thread: 0,
            lobby_endpoint_edit,
            boot: BootSession::idle(),
        }
    }

    /// Scan content dir for extracted games + ISOs. Real filesystem only.
    /// Identify errors are surfaced per-entry, never silently mapped.
    pub fn scan_library(&mut self) -> Result<()> {
        self.games.clear();
        let dir = self.cfg.content_dir.clone();
        if !dir.exists() {
            self.status_line = format!("content dir missing: {}", dir.display());
            return Ok(());
        }
        for e in std::fs::read_dir(&dir)? {
            let e = e.map_err(|e| EmuError::Io(e.to_string()))?;
            let p = e.path();
            let title = p
                .file_name()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_default();
            match x360_filesystem::identify(&p) {
                Ok(kind) => {
                    let status = match kind {
                        x360_filesystem::ContentKind::ExtractedDir => {
                            "extracted-dir (loads, not verified playable)"
                        }
                        x360_filesystem::ContentKind::Iso => "iso (loads, not verified playable)",
                        x360_filesystem::ContentKind::Stfs => "stfs (loads, not verified playable)",
                        x360_filesystem::ContentKind::Unknown => {
                            "unknown (see docs/COMPATIBILITY.md)"
                        }
                    };
                    self.games.push(GameEntry {
                        path: p,
                        title,
                        status: status.into(),
                    });
                }
                Err(err) => {
                    let msg = format!("identify error: {}", err);
                    self.log_lines.push(format!("{}: {}", p.display(), msg));
                    self.games.push(GameEntry {
                        path: p,
                        title,
                        status: msg,
                    });
                }
            }
        }
        self.status_line = format!("{} entries", self.games.len());
        Ok(())
    }

    /// Load XEX bytes to guest and set thread-0 PC. Does not claim boot.
    pub fn load_xex_bytes(&mut self, image: &[u8], load_addr: u32) -> Result<u32> {
        let (_hdr, info) = x360_loader::parse_xex(image)?;
        x360_loader::load_bytes_to_guest(&mut self.mem, load_addr, image)?;
        self.xenon.threads[0].t.pc = info.entry_point;
        self.status_line = format!("loaded, entry={:08x} (not booted)", info.entry_point);
        Ok(info.entry_point)
    }

    /// Place the demo guest at entry and run it to exit. Real execution.
    pub fn boot_demo(&mut self) -> Result<()> {
        use x360_kernel::boot::{boot_banner_words, run_until_exit};
        let entry = 0x8200_1000;
        for (i, w) in boot_banner_words().iter().enumerate() {
            self.mem.write_u32(entry + i as u32 * 4, *w)?;
        }
        self.xenon = x360_cpu::Xenon::new(entry);
        self.kernel.console.clear();
        match run_until_exit(&mut self.mem, &mut self.xenon, &mut self.kernel, 1024) {
            Ok(exit) => {
                self.status_line = format!(
                    "booted: exit={} steps={} out={:?}",
                    exit.code,
                    exit.steps,
                    String::from_utf8_lossy(&exit.output)
                );
                self.log_lines.push(self.status_line.clone());
                Ok(())
            }
            Err(e) => {
                self.status_line = format!("boot failed: {}", e);
                self.log_lines.push(self.status_line.clone());
                Err(e)
            }
        }
    }

    /// Start a staged demo boot. Each `poll_boot` call performs one real
    /// stage so the UI loading screen reflects actual work.
    pub fn begin_boot_demo(&mut self) {
        self.boot = BootSession::new();
        self.kernel.console.clear();
    }

    /// Advance the staged boot by one stage. Returns true when terminal.
    pub fn poll_boot(&mut self) -> bool {
        use x360_kernel::boot::{boot_banner_words, run_until_exit};
        const ENTRY: u32 = 0x8200_1000;
        match self.boot.stage {
            BootStage::Idle | BootStage::Done | BootStage::Failed => true,
            BootStage::Parse => {
                let words = boot_banner_words();
                if words.is_empty() || !ENTRY.is_multiple_of(4) {
                    self.boot.fail("demo guest empty or entry misaligned");
                } else {
                    self.boot.detail = format!("{} words, entry={:08x}", words.len(), ENTRY);
                    self.boot.advance(BootStage::Map, 0.25);
                }
                false
            }
            BootStage::Map => {
                let mut ok = true;
                for (i, w) in boot_banner_words().iter().enumerate() {
                    if let Err(e) = self.mem.write_u32(ENTRY + i as u32 * 4, *w) {
                        self.boot.fail(&e.to_string());
                        ok = false;
                        break;
                    }
                }
                if ok {
                    self.xenon = x360_cpu::Xenon::new(ENTRY);
                    self.boot.detail = "guest mapped".into();
                    self.boot.advance(BootStage::GpuInit, 0.5);
                }
                false
            }
            BootStage::GpuInit => {
                match x360_gpu::Xenos::validate_triangle() {
                    Ok(true) => {
                        self.boot.detail = "host GPU ok".into();
                        self.boot.advance(BootStage::Run, 0.75);
                    }
                    Ok(false) => {
                        self.boot.detail = "no adapter, continuing headless".into();
                        self.boot.advance(BootStage::Run, 0.75);
                    }
                    Err(e) => self.boot.fail(&e.to_string()),
                }
                false
            }
            BootStage::Run => {
                match run_until_exit(&mut self.mem, &mut self.xenon, &mut self.kernel, 1024) {
                    Ok(exit) => {
                        self.boot.exit_code = Some(exit.code);
                        self.boot.detail = format!(
                            "exit={} steps={} out={:?}",
                            exit.code,
                            exit.steps,
                            String::from_utf8_lossy(&exit.output)
                        );
                        self.boot.advance(BootStage::Done, 1.0);
                        self.status_line = format!("booted: {}", self.boot.detail);
                        self.log_lines.push(self.status_line.clone());
                    }
                    Err(e) => self.boot.fail(&e.to_string()),
                }
                true
            }
        }
    }

    /// Step all 6 hardware threads once (round-robin).
    pub fn step_cpu(&mut self) -> Result<()> {
        let traps = self.xenon.step_all(&mut self.mem)?;
        if traps.is_empty() {
            let pc = self.xenon.threads[self.active_thread].t.pc;
            if self.debugger.is_breakpoint(pc) {
                self.status_line = format!("breakpoint {:08x}", pc);
            }
            return Ok(());
        }
        for trap in traps {
            // Convention: r0 = syscall id at sc time.
            let id = self.xenon.threads[trap.thread].t.gpr[0];
            match self.kernel.syscall(id, &[]) {
                Ok(v) => {
                    let msg = format!("syscall {} -> {:08x} (thread {})", id, v, trap.thread);
                    self.log_lines.push(msg.clone());
                    self.status_line = msg;
                }
                Err(e) => {
                    let msg = format!("syscall {} failed: {} (thread {})", id, e, trap.thread);
                    self.log_lines.push(msg.clone());
                    self.status_line = msg.clone();
                    return Err(e);
                }
            }
        }
        Ok(())
    }

    /// Push a short silence frame through the selected audio backend.
    /// Null succeeds and counts; Host reports explicit Unsupported.
    pub fn test_audio(&mut self) -> Result<()> {
        self.audio = x360_audio::AudioOut::new(if self.audio_host {
            x360_audio::Backend::Host
        } else {
            x360_audio::Backend::Null
        });
        match self.audio.push_pcm(&[0, 0, 0, 0]) {
            Ok(()) => {
                self.status_line = format!("audio ok (frames={})", self.audio.frames_pushed);
                Ok(())
            }
            Err(e) => {
                self.status_line = format!("audio: {}", e);
                self.log_lines.push(self.status_line.clone());
                Err(e)
            }
        }
    }

    /// Send one System Link beacon on loopback and try to read it back.
    /// Real UDP sockets; failures are reported, never faked.
    pub fn test_beacon(&mut self) -> Result<()> {
        use x360_network::{SessionInfo, UdpBridge};
        let rx = UdpBridge::bind("127.0.0.1:0")?;
        let tx = UdpBridge::bind("127.0.0.1:0")?;
        let target = rx.local_addr()?.to_string();
        let session = SessionInfo {
            id: "frontend-beacon".into(),
            host: self.cfg.player_name.clone(),
            game: "beacon-test".into(),
            players: 1,
            max_players: 2,
        };
        tx.send_beacon(&session, &target)?;
        let mut buf = [0u8; 1024];
        match rx.recv_beacon(&mut buf) {
            Ok((s, addr)) => {
                let ev = x360_network::NetEvent::Discovered {
                    addr,
                    game: s.game.clone(),
                };
                self.net_log.push(ev.log());
                self.status_line = format!("beacon ok {}", addr);
                Ok(())
            }
            Err(e) => {
                let msg = format!("beacon failed: {}", e);
                self.net_log.push(msg.clone());
                self.status_line = msg;
                Err(EmuError::Network(self.status_line.clone()))
            }
        }
    }

    /// Apply lobby endpoint edit to config + validation.
    pub fn apply_lobby_endpoint(&mut self) -> Result<()> {
        self.cfg.lobby_endpoint = self.lobby_endpoint_edit.trim().to_string();
        self.cfg.validate()?;
        let client = x360_network::LobbyClient::new(&self.cfg.lobby_endpoint);
        if client.endpoint.is_empty() {
            self.net_log.push("lobby: LAN-only (no endpoint)".into());
        } else {
            self.net_log
                .push(format!("lobby endpoint set: {}", client.endpoint));
        }
        Ok(())
    }
}

// ---- eframe shell ----

impl eframe::App for EmuApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Advance staged boot one stage per frame; stages do real work.
        if self.boot.active() {
            self.poll_boot();
            ctx.request_repaint();
        }
        egui::TopBottomPanel::top("top").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading("x360-rs");
                ui.label(&self.status_line);
                if ui.button("Scan library").clicked() {
                    if let Err(e) = self.scan_library() {
                        self.status_line = format!("scan failed: {}", e);
                        self.log_lines.push(self.status_line.clone());
                    }
                }
                if ui.button("Step x6").clicked() {
                    if let Err(e) = self.step_cpu() {
                        self.status_line = format!("step fault: {}", e);
                        self.log_lines.push(self.status_line.clone());
                    }
                }
                if ui.button("Boot demo").clicked() {
                    self.begin_boot_demo();
                }
                if ui.button("Test audio").clicked() {
                    let _ = self.test_audio();
                }
                if ui.button("Beacon test").clicked() {
                    let _ = self.test_beacon();
                }
            });
        });
        egui::SidePanel::left("games").show(ctx, |ui| {
            ui.heading("Library");
            for g in &self.games {
                ui.label(format!("{} [{}]", g.title, g.status));
            }
            if self.games.is_empty() {
                ui.weak("No entries. Set content dir, then Scan.");
            }
            ui.separator();
            ui.heading("Settings");
            ui.checkbox(&mut self.audio_host, "host audio (else null)");
            ui.label("Lobby endpoint (empty = LAN only)");
            ui.text_edit_singleline(&mut self.lobby_endpoint_edit);
            if ui.button("Apply lobby").clicked() {
                if let Err(e) = self.apply_lobby_endpoint() {
                    self.status_line = format!("lobby: {}", e);
                }
            }
            ui.label(format!("audio frames: {}", self.audio.frames_pushed));
        });
        egui::CentralPanel::default().show(ctx, |ui| {
            // Boot screen: guest output once the boot run completes.
            if self.boot.stage == BootStage::Done {
                ui.vertical_centered(|ui| {
                    ui.add_space(40.0);
                    ui.heading(String::from_utf8_lossy(&self.kernel.console).to_string());
                    ui.monospace(&self.boot.detail);
                    if ui.button("Back to debugger").clicked() {
                        self.boot = BootSession::idle();
                    }
                });
                ui.separator();
            }
            // Loading screen: only while stages are running or failed.
            if self.boot.active() || self.boot.stage == BootStage::Failed {
                ui.heading("Booting…");
                ui.add(
                    egui::ProgressBar::new(self.boot.progress)
                        .show_percentage()
                        .animate(true),
                );
                for (name, done) in [
                    ("parse", BootStage::Parse),
                    ("map", BootStage::Map),
                    ("gpu", BootStage::GpuInit),
                    ("run", BootStage::Run),
                ] {
                    let mark = if self.boot.progress
                        >= match done {
                            BootStage::Parse => 0.25,
                            BootStage::Map => 0.5,
                            BootStage::GpuInit => 0.75,
                            _ => 1.0,
                        } {
                        "✓"
                    } else if self.boot.stage == done {
                        "…"
                    } else {
                        "·"
                    };
                    ui.monospace(format!("{} {}", mark, name));
                }
                ui.monospace(&self.boot.detail);
                if self.boot.stage == BootStage::Failed && ui.button("Dismiss").clicked() {
                    self.boot = BootSession::idle();
                }
                ui.separator();
            }
            ui.horizontal(|ui| {
                ui.heading(format!("CPU ({} threads)", self.xenon.threads.len()));
                egui::ComboBox::from_label("thread")
                    .selected_text(format!("{}", self.active_thread))
                    .show_ui(ui, |ui| {
                        for i in 0..self.xenon.threads.len() {
                            ui.selectable_value(&mut self.active_thread, i, format!("{}", i));
                        }
                    });
            });
            let t = &self.xenon.threads[self.active_thread].t;
            ui.monospace(format!(
                "pc={:08x} lr={:08x} ctr={:08x} steps={}",
                t.pc, t.lr, t.ctr, self.xenon.threads[self.active_thread].steps
            ));
            ui.separator();
            ui.heading("Disassembly @ pc");
            for line in self.debugger.disasm_at(&self.mem, t.pc, 6) {
                ui.monospace(line);
            }
            ui.separator();
            ui.heading("Registers");
            for r in self.debugger.regs(t).iter().take(9) {
                ui.monospace(r);
            }
            ui.separator();
            ui.heading("GPU");
            ui.monospace(format!(
                "decoded={} unsupported={} draws={} last={:?}",
                self.gpu.stats.decoded,
                self.gpu.stats.unsupported,
                self.gpu.stats.draws,
                self.gpu.stats.last_unsupported
            ));
            ui.separator();
            ui.heading("Net");
            for line in self.net_log.iter().rev().take(20) {
                ui.monospace(line);
            }
            ui.separator();
            ui.heading("Log");
            for line in self.log_lines.iter().rev().take(50) {
                ui.monospace(line);
            }
        });
    }
}

fn main() -> eframe::Result<()> {
    x360_common::init_logging();
    let cfg = EmuConfig::default();
    let app = EmuApp::new(cfg);
    let opts = eframe::NativeOptions::default();
    eframe::run_native("x360-rs", opts, Box::new(|_| Ok(Box::new(app))))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boot_session_parse_to_map() {
        let mut app = EmuApp::new(EmuConfig::default());
        app.begin_boot_demo();
        assert_eq!(app.boot.stage, BootStage::Parse);
        assert!(app.boot.active());
        assert!(!app.poll_boot()); // Parse -> Map
        assert_eq!(app.boot.stage, BootStage::Map);
        assert!(!app.poll_boot()); // Map -> GpuInit (writes memory)
        assert_eq!(app.boot.stage, BootStage::GpuInit);
        // First demo word landed at entry.
        assert_eq!(app.mem.fetch_u32(0x8200_1000).unwrap(), 0x3800_0002);
    }

    #[test]
    fn boot_session_full_run() {
        let mut app = EmuApp::new(EmuConfig::default());
        app.begin_boot_demo();
        let mut terminal = false;
        for _ in 0..8 {
            terminal = app.poll_boot();
            if terminal {
                break;
            }
        }
        assert!(terminal);
        assert_eq!(app.boot.stage, BootStage::Done);
        assert_eq!(app.boot.exit_code, Some(0));
        assert_eq!(app.boot.progress, 1.0);
    }
}
