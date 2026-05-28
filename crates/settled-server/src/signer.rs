use std::path::{Path, PathBuf};
use std::sync::RwLock;

use ed25519_dalek::{Signer as DalekSigner, SigningKey};
use rand::rngs::OsRng;

pub trait Signer: Send + Sync {
    fn sign(&self, payload: &[u8; 48]) -> [u8; 64];
    fn public_key(&self) -> [u8; 32];
    fn key_version(&self) -> u32;
}

struct SignerInner {
    key: SigningKey,
    version: u32,
}

pub struct LocalSigner {
    inner: RwLock<SignerInner>,
    key_path: PathBuf,
}

impl LocalSigner {
    pub fn load_or_generate(path: &Path, version: u32) -> anyhow::Result<Self> {
        let key = if path.exists() {
            let bytes = std::fs::read(path)?;
            let arr: [u8; 32] = bytes
                .try_into()
                .map_err(|_| anyhow::anyhow!("signing key file must be exactly 32 bytes"))?;
            SigningKey::from_bytes(&arr)
        } else {
            let key = SigningKey::generate(&mut OsRng);
            std::fs::write(path, key.to_bytes())?;
            tracing::info!("Generated new signing key at {}", path.display());
            key
        };
        Ok(Self {
            inner: RwLock::new(SignerInner { key, version }),
            key_path: path.to_path_buf(),
        })
    }

    /// Generate a new key, persist it, and hot-swap. Returns the new public key bytes.
    pub fn rotate(&self, new_version: u32) -> anyhow::Result<[u8; 32]> {
        let new_key = SigningKey::generate(&mut OsRng);
        let new_pubkey = new_key.verifying_key().to_bytes();
        std::fs::write(&self.key_path, new_key.to_bytes())?;
        let mut inner = self.inner.write().unwrap();
        inner.key = new_key;
        inner.version = new_version;
        tracing::info!("Rotated to key version {new_version}");
        Ok(new_pubkey)
    }
}

impl Signer for LocalSigner {
    fn sign(&self, payload: &[u8; 48]) -> [u8; 64] {
        self.inner.read().unwrap().key.sign(payload).to_bytes()
    }

    fn public_key(&self) -> [u8; 32] {
        self.inner.read().unwrap().key.verifying_key().to_bytes()
    }

    fn key_version(&self) -> u32 {
        self.inner.read().unwrap().version
    }
}
