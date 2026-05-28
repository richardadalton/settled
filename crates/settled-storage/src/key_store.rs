use std::sync::Arc;

use prost::Message;
use rocksdb::IteratorMode;

use crate::db::{DbInner, CF_KEYS};
use crate::error::{Error, Result};
use crate::proto::KeyRecordProto;

#[derive(Debug, Clone)]
pub struct KeyRecord {
    pub version: u32,
    pub public_key: [u8; 32],
    pub activated_at_tree_size: u64,
}

#[derive(Clone)]
pub struct KeyStore(pub(crate) Arc<DbInner>);

impl KeyStore {
    pub fn put(&self, record: &KeyRecord) -> Result<()> {
        let cf = self.0.db.cf_handle(CF_KEYS).expect("keys CF must exist");
        let proto = KeyRecordProto {
            version: record.version,
            public_key: record.public_key.to_vec(),
            activated_at_tree_size: record.activated_at_tree_size,
        };
        let mut buf = Vec::new();
        proto.encode(&mut buf)?;
        self.0.db.put_cf(cf, record.version.to_be_bytes(), &buf)?;
        Ok(())
    }

    pub fn get(&self, version: u32) -> Result<Option<KeyRecord>> {
        let cf = self.0.db.cf_handle(CF_KEYS).expect("keys CF must exist");
        match self.0.db.get_cf(cf, version.to_be_bytes())? {
            Some(v) => Ok(Some(decode(&v)?)),
            None => Ok(None),
        }
    }

    /// Returns the record with the highest version, or None if the store is empty.
    pub fn latest(&self) -> Result<Option<KeyRecord>> {
        let cf = self.0.db.cf_handle(CF_KEYS).expect("keys CF must exist");
        let mut iter = self.0.db.iterator_cf(cf, IteratorMode::End);
        match iter.next() {
            Some(Ok((_, v))) => Ok(Some(decode(&v)?)),
            Some(Err(e)) => Err(e.into()),
            None => Ok(None),
        }
    }

    /// Returns all records ordered by version ascending.
    pub fn all(&self) -> Result<Vec<KeyRecord>> {
        let cf = self.0.db.cf_handle(CF_KEYS).expect("keys CF must exist");
        let iter = self.0.db.iterator_cf(cf, IteratorMode::Start);
        let mut records = Vec::new();
        for item in iter {
            let (_, v) = item?;
            records.push(decode(&v)?);
        }
        Ok(records)
    }
}

fn decode(bytes: &[u8]) -> Result<KeyRecord> {
    let proto = KeyRecordProto::decode(bytes)?;
    let public_key: [u8; 32] = proto
        .public_key
        .try_into()
        .map_err(|_| Error::Corruption("KeyRecord public_key must be 32 bytes".into()))?;
    Ok(KeyRecord {
        version: proto.version,
        public_key,
        activated_at_tree_size: proto.activated_at_tree_size,
    })
}
