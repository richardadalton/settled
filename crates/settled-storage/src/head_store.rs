use std::sync::Arc;

use prost::Message;
use rocksdb::{Direction, IteratorMode, WriteBatch};

use crate::db::{DbInner, CF_HEADS};
use crate::error::{Error, Result};
use crate::proto::SignedTreeHeadProto;
use crate::types::SignedTreeHead;

#[derive(Clone)]
pub struct HeadStore(pub(crate) Arc<DbInner>);

impl HeadStore {
    pub fn write(&self, sth: &SignedTreeHead) -> Result<()> {
        let cf = self.0.db.cf_handle(CF_HEADS).expect("heads CF must exist");
        let proto = SignedTreeHeadProto::from(sth);
        let mut buf = Vec::new();
        proto.encode(&mut buf)?;
        let mut batch = WriteBatch::default();
        batch.put_cf(cf, sth.tree_size.to_be_bytes(), &buf);
        self.0.db.write(batch)?;
        Ok(())
    }

    pub fn latest(&self) -> Result<Option<SignedTreeHead>> {
        let cf = self.0.db.cf_handle(CF_HEADS).expect("heads CF must exist");
        let mut iter = self.0.db.iterator_cf(cf, IteratorMode::End);
        match iter.next() {
            Some(Ok((_, v))) => {
                let proto = SignedTreeHeadProto::decode(v.as_ref())?;
                Ok(Some(SignedTreeHead::try_from(proto)?))
            }
            Some(Err(e)) => Err(e.into()),
            None => Ok(None),
        }
    }

    /// Returns the STH with exactly `tree_size`, or None if no such STH exists.
    pub fn at_size(&self, tree_size: u64) -> Result<Option<SignedTreeHead>> {
        let cf = self.0.db.cf_handle(CF_HEADS).expect("heads CF must exist");
        match self.0.db.get_cf(cf, tree_size.to_be_bytes())? {
            Some(v) => {
                let proto = SignedTreeHeadProto::decode(v.as_ref())?;
                Ok(Some(SignedTreeHead::try_from(proto)?))
            }
            None => Ok(None),
        }
    }

    /// Returns all STHs with tree_size in `[from_size, to_size]` (inclusive), ordered ascending.
    pub fn range(&self, from_size: u64, to_size: u64) -> Result<Vec<SignedTreeHead>> {
        let cf = self.0.db.cf_handle(CF_HEADS).expect("heads CF must exist");
        let from_bytes = from_size.to_be_bytes();
        let iter = self
            .0
            .db
            .iterator_cf(cf, IteratorMode::From(&from_bytes, Direction::Forward));
        let mut result = Vec::new();
        for item in iter {
            let (k, v) = item?;
            let size = u64::from_be_bytes(
                k.as_ref()
                    .try_into()
                    .map_err(|_| Error::Corruption("bad tree_size key length".into()))?,
            );
            if size > to_size {
                break;
            }
            let proto = SignedTreeHeadProto::decode(v.as_ref())?;
            result.push(SignedTreeHead::try_from(proto)?);
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Db;
    use tempfile::TempDir;

    fn open_fresh() -> (TempDir, Db) {
        let dir = TempDir::new().unwrap();
        let db = Db::open(dir.path()).unwrap();
        (dir, db)
    }

    fn fake_sth(tree_size: u64) -> SignedTreeHead {
        SignedTreeHead {
            tree_size,
            root_hash: [tree_size as u8; 32],
            timestamp_ns: tree_size as i64 * 1_000_000,
            signature: [0u8; 64],
            public_key: [0u8; 32],
            key_version: 1,
        }
    }

    #[test]
    fn latest_returns_largest_tree_size() {
        let (_dir, db) = open_fresh();
        let heads = db.head_store();
        for size in [1u64, 5, 3, 10, 7] {
            heads.write(&fake_sth(size)).unwrap();
        }
        let latest = heads.latest().unwrap().unwrap();
        assert_eq!(latest.tree_size, 10);
    }

    #[test]
    fn at_size_returns_exact_match() {
        let (_dir, db) = open_fresh();
        let heads = db.head_store();
        for size in 1u64..=10 {
            heads.write(&fake_sth(size)).unwrap();
        }
        let sth = heads.at_size(7).unwrap().unwrap();
        assert_eq!(sth.tree_size, 7);
    }

    #[test]
    fn at_size_missing_returns_none() {
        let (_dir, db) = open_fresh();
        let heads = db.head_store();
        heads.write(&fake_sth(5)).unwrap();
        heads.write(&fake_sth(10)).unwrap();
        assert!(heads.at_size(7).unwrap().is_none());
    }

    #[test]
    fn range_returns_correct_subset() {
        let (_dir, db) = open_fresh();
        let heads = db.head_store();
        for size in 1u64..=10 {
            heads.write(&fake_sth(size)).unwrap();
        }
        let result = heads.range(3, 6).unwrap();
        assert_eq!(result.len(), 4);
        assert_eq!(result[0].tree_size, 3);
        assert_eq!(result[3].tree_size, 6);
    }

    #[test]
    fn latest_on_empty_store_returns_none() {
        let (_dir, db) = open_fresh();
        assert!(db.head_store().latest().unwrap().is_none());
    }
}
