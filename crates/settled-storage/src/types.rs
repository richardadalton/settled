use crate::error::{Error, Result};
use crate::proto::{LogEntryProto, SignedTreeHeadProto};

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
            .map_err(|_| Error::Corruption("signature must be 32 bytes".into()))?;
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
