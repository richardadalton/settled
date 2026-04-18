use std::sync::Arc;

use prost::Message;

use crate::db::{DbInner, CF_SETTLEDES};
use crate::error::{Error, Result};
use crate::types::SettledRecord;

// ── Proto ─────────────────────────────────────────────────────────────────────

#[derive(Clone, PartialEq, prost::Message)]
pub(crate) struct SettledRecordProto {
    #[prost(string, tag = "1")]
    pub url: String,
    #[prost(bytes = "vec", tag = "2")]
    pub public_key: Vec<u8>,
    #[prost(uint32, tag = "3")]
    pub consecutive_failures: u32,
    #[prost(bool, tag = "4")]
    pub flagged_dead: bool,
    #[prost(int64, tag = "5")]
    pub registered_at_ns: i64,
}

fn to_proto(r: &SettledRecord) -> SettledRecordProto {
    SettledRecordProto {
        url: r.url.clone(),
        public_key: r.public_key.map(|k| k.to_vec()).unwrap_or_default(),
        consecutive_failures: r.consecutive_failures,
        flagged_dead: r.flagged_dead,
        registered_at_ns: r.registered_at_ns,
    }
}

fn from_proto(p: SettledRecordProto) -> Result<SettledRecord> {
    let public_key = if p.public_key.is_empty() {
        None
    } else {
        let arr: [u8; 32] = p
            .public_key
            .try_into()
            .map_err(|_| Error::Corruption("settled record public_key must be 32 bytes".into()))?;
        Some(arr)
    };
    Ok(SettledRecord {
        url: p.url,
        public_key,
        consecutive_failures: p.consecutive_failures,
        flagged_dead: p.flagged_dead,
        registered_at_ns: p.registered_at_ns,
    })
}

// ── Store ─────────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct SettledStore(pub(crate) Arc<DbInner>);

impl SettledStore {
    pub fn register(&self, record: &SettledRecord) -> Result<()> {
        let cf = self.0.db.cf_handle(CF_SETTLEDES).expect("settledes CF missing");
        let bytes = to_proto(record).encode_to_vec();
        self.0.db.put_cf(&cf, record.url.as_bytes(), bytes)?;
        Ok(())
    }

    pub fn get(&self, url: &str) -> Result<Option<SettledRecord>> {
        let cf = self.0.db.cf_handle(CF_SETTLEDES).expect("settledes CF missing");
        match self.0.db.get_cf(&cf, url.as_bytes())? {
            None => Ok(None),
            Some(bytes) => {
                let proto = SettledRecordProto::decode(bytes.as_slice())
                    .map_err(|e| Error::Corruption(format!("settled_store decode: {e}")))?;
                Ok(Some(from_proto(proto)?))
            }
        }
    }

    pub fn update(&self, record: &SettledRecord) -> Result<()> {
        self.register(record)
    }

    pub fn delete(&self, url: &str) -> Result<()> {
        let cf = self.0.db.cf_handle(CF_SETTLEDES).expect("settledes CF missing");
        self.0.db.delete_cf(&cf, url.as_bytes())?;
        Ok(())
    }

    pub fn list(&self) -> Result<Vec<SettledRecord>> {
        let cf = self.0.db.cf_handle(CF_SETTLEDES).expect("settledes CF missing");
        let mut records = Vec::new();
        for item in self.0.db.iterator_cf(&cf, rocksdb::IteratorMode::Start) {
            let (_, value) = item?;
            let proto = SettledRecordProto::decode(value.as_ref())
                .map_err(|e| Error::Corruption(format!("settled_store decode: {e}")))?;
            records.push(from_proto(proto)?);
        }
        Ok(records)
    }

    /// Returns all non-dead records.
    pub fn live(&self) -> Result<Vec<SettledRecord>> {
        Ok(self.list()?.into_iter().filter(|r| !r.flagged_dead).collect())
    }
}
