/// Per-TCP-connection volatile state.
///
/// On a real ATECC608A this lives in on-chip SRAM and is cleared on
/// sleep/idle. We model that by owning a `Session` per connection, and wiping
/// it when we see a 0x01 (sleep) or 0x02 (idle) word-address byte.
use sha2::{Digest, Sha256};

/// Which source populated TempKey. Sign/Verify pick different paths based on
/// this so we track it explicitly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TempKeySource {
    /// Loaded by a Nonce command in pass-through mode (mode=0x03). The 32
    /// bytes are the caller-supplied message directly. This is the path
    /// wolfSSL uses to set up an ECDSA Sign.
    NoncePassThrough,
}

#[derive(Debug, Clone, Default)]
pub struct TempKey {
    pub value: [u8; 32],
    pub valid: bool,
    pub source: Option<TempKeySource>,
}

impl TempKey {
    pub fn load_passthrough(&mut self, data: &[u8; 32]) {
        self.value = *data;
        self.valid = true;
        self.source = Some(TempKeySource::NoncePassThrough);
    }
    pub fn clear(&mut self) {
        self.value = [0; 32];
        self.valid = false;
        self.source = None;
    }
}

/// Multi-step SHA-256 context held between SHA init / update / end commands.
#[derive(Default)]
pub struct ShaCtx {
    pub hasher: Option<Sha256>,
}

impl ShaCtx {
    pub fn start(&mut self) {
        self.hasher = Some(Sha256::new());
    }
    pub fn update(&mut self, data: &[u8]) -> bool {
        if let Some(h) = self.hasher.as_mut() {
            h.update(data);
            true
        } else {
            false
        }
    }
    pub fn finish(&mut self, trailing: &[u8]) -> Option<[u8; 32]> {
        let h = self.hasher.take()?;
        let digest = if trailing.is_empty() {
            h.finalize()
        } else {
            let mut h = h;
            h.update(trailing);
            h.finalize()
        };
        Some(digest.into())
    }
    pub fn clear(&mut self) {
        self.hasher = None;
    }
}

#[derive(Default)]
pub struct Session {
    pub tempkey: TempKey,
    pub sha: ShaCtx,
}

impl Session {
    pub fn new() -> Self {
        Self::default()
    }
    /// Called when the host asserts idle/sleep. Real hardware clears all
    /// volatile state; mirror that.
    pub fn volatile_reset(&mut self) {
        self.tempkey.clear();
        self.sha.clear();
    }
}
