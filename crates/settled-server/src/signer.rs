use ed25519_dalek::{Signer as DalekSigner, SigningKey};
use rand::rngs::OsRng;
use std::path::Path;

pub trait Signer: Send + Sync {
    fn sign(&self, payload: &[u8; 48]) -> [u8; 64];
    fn public_key(&self) -> [u8; 32];
    fn key_version(&self) -> u32;
}

pub struct LocalSigner {
    key: SigningKey,
    version: u32,
}

impl LocalSigner {
    pub fn load_or_generate(path: &Path) -> anyhow::Result<Self> {
        if path.exists() {
            let bytes = std::fs::read(path)?;
            let arr: [u8; 32] = bytes
                .try_into()
                .map_err(|_| anyhow::anyhow!("signing key file must be exactly 32 bytes"))?;
            Ok(Self {
                key: SigningKey::from_bytes(&arr),
                version: 1,
            })
        } else {
            let key = SigningKey::generate(&mut OsRng);
            std::fs::write(path, key.to_bytes())?;
            tracing::info!("Generated new signing key at {}", path.display());
            Ok(Self { key, version: 1 })
        }
    }
}

impl Signer for LocalSigner {
    fn sign(&self, payload: &[u8; 48]) -> [u8; 64] {
        self.key.sign(payload).to_bytes()
    }

    fn public_key(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }

    fn key_version(&self) -> u32 {
        self.version
    }
}
