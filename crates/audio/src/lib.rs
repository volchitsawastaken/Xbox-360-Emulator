//! Audio output and XMA tracking.

use x360_common::{EmuError, Result};

/// Audio backend selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    Null,
    Host,
}

/// Null sink always works; host output pending real backend (M6+).
pub struct AudioOut {
    backend: Backend,
    pub frames_pushed: u64,
    pub xma_attempts: u64,
}

impl AudioOut {
    pub fn new(backend: Backend) -> Self {
        Self {
            backend,
            frames_pushed: 0,
            xma_attempts: 0,
        }
    }

    pub fn push_pcm(&mut self, frames: &[i16]) -> Result<()> {
        if frames.is_empty() {
            return Ok(());
        }
        match self.backend {
            Backend::Null => {
                self.frames_pushed += (frames.len() / 2) as u64;
                Ok(())
            }
            Backend::Host => Err(EmuError::Unsupported(
                "host audio (cpal) not wired yet".into(),
            )),
        }
    }

    /// XMA decode: explicitly unsupported until validated.
    pub fn decode_xma(&mut self, _data: &[u8]) -> Result<Vec<i16>> {
        self.xma_attempts += 1;
        log::warn!(
            "audio: XMA decode requested, unsupported (attempt {})",
            self.xma_attempts
        );
        Err(EmuError::Unsupported("XMA decode not implemented".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn null_sink_counts() {
        let mut a = AudioOut::new(Backend::Null);
        a.push_pcm(&[0, 0, 1, 1]).unwrap();
        assert_eq!(a.frames_pushed, 2);
    }
    #[test]
    fn xma_is_explicit() {
        let mut a = AudioOut::new(Backend::Null);
        assert!(a.decode_xma(&[1, 2, 3]).is_err());
    }

    #[test]
    fn host_without_backend_is_explicit() {
        let mut a = AudioOut::new(Backend::Host);
        assert!(a.push_pcm(&[0, 0]).is_err());
    }
}
