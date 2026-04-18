use std::sync::Arc;

use prost::Message;

use crate::db::{DbInner, CF_FINAL_HEADS};
use crate::error::{Error, Result};
use crate::proto::FinalSTHProto;
use crate::types::FinalSTH;

#[derive(Clone)]
pub struct FinalHeadStore(pub(crate) Arc<DbInner>);

impl FinalHeadStore {
    pub fn write(&self, f: &FinalSTH) -> Result<()> {
        let cf = self.0.db.cf_handle(CF_FINAL_HEADS).expect("final_heads CF missing");
        let key = f.sth.tree_size.to_be_bytes();
        let bytes = FinalSTHProto::from(f).encode_to_vec();
        self.0.db.put_cf(&cf, key, bytes)?;
        Ok(())
    }

    pub fn get(&self, tree_size: u64) -> Result<Option<FinalSTH>> {
        let cf = self.0.db.cf_handle(CF_FINAL_HEADS).expect("final_heads CF missing");
        match self.0.db.get_cf(&cf, tree_size.to_be_bytes())? {
            None => Ok(None),
            Some(bytes) => {
                let proto = FinalSTHProto::decode(bytes.as_slice())
                    .map_err(|e| Error::Corruption(format!("final_head decode: {e}")))?;
                Ok(Some(proto.try_into()?))
            }
        }
    }

    pub fn latest(&self) -> Result<Option<FinalSTH>> {
        let cf = self.0.db.cf_handle(CF_FINAL_HEADS).expect("final_heads CF missing");
        let mut iter = self.0.db.iterator_cf(&cf, rocksdb::IteratorMode::End);
        match iter.next() {
            None => Ok(None),
            Some(item) => {
                let (_, value) = item?;
                let proto = FinalSTHProto::decode(value.as_ref())
                    .map_err(|e| Error::Corruption(format!("final_head decode: {e}")))?;
                Ok(Some(proto.try_into()?))
            }
        }
    }
}
