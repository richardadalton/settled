use crate::error::{Error, Result};
use crate::proto::{CounterSignatureProto, FinalSTHProto, LogEntryProto, SignedTreeHeadProto};

#[derive(Debug, Clone)]
pub struct LogEntry {
    pub seq: u64,
    pub timestamp_ns: i64,
    pub key: Vec<u8>,
    pub data: Vec<u8>,
    pub leaf_hash: [u8; 32],
}

impl TryFrom<LogEntryProto> for LogEntry {
    type Error = Error;

    fn try_from(p: LogEntryProto) -> Result<Self> {
        let leaf_hash: [u8; 32] = p
            .leaf_hash
            .try_into()
            .map_err(|_| Error::Corruption("leaf_hash must be 32 bytes".into()))?;
        Ok(LogEntry {
            seq: p.seq,
            timestamp_ns: p.timestamp_ns,
            key: p.key,
            data: p.data,
            leaf_hash,
        })
    }
}

impl From<&LogEntry> for LogEntryProto {
    fn from(e: &LogEntry) -> Self {
        LogEntryProto {
            seq: e.seq,
            timestamp_ns: e.timestamp_ns,
            key: e.key.clone(),
            data: e.data.clone(),
            leaf_hash: e.leaf_hash.to_vec(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SignedTreeHead {
    pub tree_size: u64,
    pub root_hash: [u8; 32],
    pub timestamp_ns: i64,
    pub signature: [u8; 64],
    pub public_key: [u8; 32],
    pub key_version: u32,
}

impl TryFrom<SignedTreeHeadProto> for SignedTreeHead {
    type Error = Error;

    fn try_from(p: SignedTreeHeadProto) -> Result<Self> {
        let root_hash: [u8; 32] = p
            .root_hash
            .try_into()
            .map_err(|_| Error::Corruption("root_hash must be 32 bytes".into()))?;
        let signature: [u8; 64] = p
            .signature
            .try_into()
            .map_err(|_| Error::Corruption("signature must be 64 bytes".into()))?;
        let public_key: [u8; 32] = p
            .public_key
            .try_into()
            .map_err(|_| Error::Corruption("public_key must be 32 bytes".into()))?;
        Ok(SignedTreeHead {
            tree_size: p.tree_size,
            root_hash,
            timestamp_ns: p.timestamp_ns,
            signature,
            public_key,
            key_version: p.key_version,
        })
    }
}

impl From<&SignedTreeHead> for SignedTreeHeadProto {
    fn from(s: &SignedTreeHead) -> Self {
        SignedTreeHeadProto {
            tree_size: s.tree_size,
            root_hash: s.root_hash.to_vec(),
            timestamp_ns: s.timestamp_ns,
            signature: s.signature.to_vec(),
            public_key: s.public_key.to_vec(),
            key_version: s.key_version,
        }
    }
}

// ── Settled registry ──────────────────────────────────────────────────────────

/// A registered external observer (settled node).
#[derive(Debug, Clone)]
pub struct SettledRecord {
    pub url: String,
    /// Ed25519 public key learned from the first counter-signature response.
    pub public_key: Option<[u8; 32]>,
    pub consecutive_failures: u32,
    pub flagged_dead: bool,
    pub registered_at_ns: i64,
}

// ── FinalSTH & counter-signatures ─────────────────────────────────────────────

/// An Ed25519 counter-signature from a settled node over the same
/// 48-byte payload as the main STH signature.
#[derive(Debug, Clone)]
pub struct CounterSignature {
    pub settled_node_url: String,
    pub public_key: [u8; 32],
    pub signature: [u8; 64],
}

/// A Signed Tree Head plus counter-signatures from settled nodes.
#[derive(Debug, Clone)]
pub struct FinalSTH {
    pub sth: SignedTreeHead,
    pub counter_signatures: Vec<CounterSignature>,
}

impl TryFrom<FinalSTHProto> for FinalSTH {
    type Error = Error;

    fn try_from(p: FinalSTHProto) -> Result<Self> {
        let sth = p
            .sth
            .ok_or_else(|| Error::Corruption("FinalSTH missing sth field".into()))?
            .try_into()?;
        let counter_signatures = p
            .counter_signatures
            .into_iter()
            .map(|c| {
                let public_key: [u8; 32] = c
                    .public_key
                    .try_into()
                    .map_err(|_| Error::Corruption("counter_signature public_key must be 32 bytes".into()))?;
                let signature: [u8; 64] = c
                    .signature
                    .try_into()
                    .map_err(|_| Error::Corruption("counter_signature signature must be 64 bytes".into()))?;
                Ok(CounterSignature { settled_node_url: c.settled_node_url, public_key, signature })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(FinalSTH { sth, counter_signatures })
    }
}

impl From<&FinalSTH> for FinalSTHProto {
    fn from(f: &FinalSTH) -> Self {
        FinalSTHProto {
            sth: Some((&f.sth).into()),
            counter_signatures: f
                .counter_signatures
                .iter()
                .map(|c| CounterSignatureProto {
                    settled_node_url: c.settled_node_url.clone(),
                    public_key: c.public_key.to_vec(),
                    signature: c.signature.to_vec(),
                })
                .collect(),
        }
    }
}
