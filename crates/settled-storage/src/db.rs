use std::path::Path;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use rocksdb::{ColumnFamilyDescriptor, DBCompressionType, Options, DB};

use crate::error::{Error, Result};

pub(crate) const CF_LOG: &str = "log";
pub(crate) const CF_TREE: &str = "tree";
pub(crate) const CF_HEADS: &str = "heads";
pub(crate) const CF_INDEX: &str = "index";
pub(crate) const CF_KEYS: &str = "keys";

const SCHEMA_VERSION_KEY: &[u8] = b"schema_version";
const CURRENT_SCHEMA_VERSION: u32 = 1;

pub(crate) struct DbInner {
    pub db: DB,
    pub next_seq: AtomicU64,
}

// SAFETY: DB and AtomicU64 are both Send + Sync.
unsafe impl Send for DbInner {}
unsafe impl Sync for DbInner {}

#[derive(Clone)]
pub struct Db(pub(crate) Arc<DbInner>);

impl Db {
    pub fn open(path: &Path) -> Result<Self> {
        let mut db_opts = Options::default();
        db_opts.create_if_missing(true);
        db_opts.create_missing_column_families(true);
        db_opts.set_compression_type(DBCompressionType::Lz4);

        let cf_names = [CF_LOG, CF_TREE, CF_HEADS, CF_INDEX, CF_KEYS];
        let cf_descriptors: Vec<ColumnFamilyDescriptor> = cf_names
            .iter()
            .map(|name| ColumnFamilyDescriptor::new(*name, Options::default()))
            .collect();

        let db = DB::open_cf_descriptors(&db_opts, path, cf_descriptors)?;

        // Check / initialise schema version.
        match db.get(SCHEMA_VERSION_KEY)? {
            None => {
                db.put(SCHEMA_VERSION_KEY, CURRENT_SCHEMA_VERSION.to_be_bytes())?;
            }
            Some(v) => {
                let version = u32::from_be_bytes(
                    (*v).try_into()
                        .map_err(|_| Error::Corruption("bad schema_version length".into()))?,
                );
                if version > CURRENT_SCHEMA_VERSION {
                    return Err(Error::SchemaMismatch {
                        found: version,
                        supported: CURRENT_SCHEMA_VERSION,
                    });
                }
            }
        }

        // Initialise next_seq from the last key in the log CF.
        let next_seq = {
            let cf = db.cf_handle(CF_LOG).expect("log CF must exist");
            let mut iter = db.iterator_cf(cf, rocksdb::IteratorMode::End);
            match iter.next() {
                Some(Ok((k, _))) => {
                    let bytes: [u8; 8] = (*k)
                        .try_into()
                        .map_err(|_| Error::Corruption("bad seq key length".into()))?;
                    u64::from_be_bytes(bytes) + 1
                }
                Some(Err(e)) => return Err(e.into()),
                None => 0,
            }
        };

        Ok(Db(Arc::new(DbInner {
            db,
            next_seq: AtomicU64::new(next_seq),
        })))
    }

    pub fn log_store(&self) -> crate::log_store::LogStore {
        crate::log_store::LogStore(self.0.clone())
    }

    pub fn tree_store(&self) -> crate::tree_store::TreeStore {
        crate::tree_store::TreeStore(self.0.clone())
    }

    pub fn head_store(&self) -> crate::head_store::HeadStore {
        crate::head_store::HeadStore(self.0.clone())
    }

    pub fn key_store(&self) -> crate::key_store::KeyStore {
        crate::key_store::KeyStore(self.0.clone())
    }
}
