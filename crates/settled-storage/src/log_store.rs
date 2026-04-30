use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use prost::Message;
use rocksdb::{Direction, IteratorMode, WriteBatch};

use crate::db::{DbInner, CF_INDEX, CF_LOG};
use crate::error::{Error, Result};
use crate::proto::LogEntryProto;
use crate::types::LogEntry;

#[derive(Clone)]
pub struct LogStore(pub(crate) Arc<DbInner>);

impl LogStore {
    /// Append a new entry. Returns `(seq, timestamp_ns)`.
    pub fn append(&self, key: &[u8], data: &[u8]) -> Result<(u64, i64)> {
        let seq = self.0.next_seq.fetch_add(1, Ordering::SeqCst);
        let timestamp_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as i64;
        let leaf_hash = settled_core::hash::leaf_hash(data);

        let proto = LogEntryProto {
            seq,
            timestamp_ns,
            key: key.to_vec(),
            data: data.to_vec(),
            leaf_hash: leaf_hash.to_vec(),
        };

        let mut value_buf = Vec::new();
        proto.encode(&mut value_buf)?;

        let seq_key = seq.to_be_bytes();

        let mut batch = WriteBatch::default();
        {
            let cf_log = self.0.db.cf_handle(CF_LOG).expect("log CF must exist");
            let cf_index = self.0.db.cf_handle(CF_INDEX).expect("index CF must exist");
            batch.put_cf(cf_log, seq_key, &value_buf);
            batch.put_cf(cf_index, key, seq_key);
        }
        self.0.db.write(batch)?;

        Ok((seq, timestamp_ns))
    }

    pub fn get_by_seq(&self, seq: u64) -> Result<Option<LogEntry>> {
        let cf = self.0.db.cf_handle(CF_LOG).expect("log CF must exist");
        match self.0.db.get_cf(cf, seq.to_be_bytes())? {
            Some(v) => {
                let proto = LogEntryProto::decode(v.as_ref())?;
                Ok(Some(LogEntry::try_from(proto)?))
            }
            None => Ok(None),
        }
    }

    pub fn get_seq_by_key(&self, key: &[u8]) -> Result<Option<u64>> {
        let cf = self.0.db.cf_handle(CF_INDEX).expect("index CF must exist");
        match self.0.db.get_cf(cf, key)? {
            Some(v) => {
                let bytes: [u8; 8] = (*v)
                    .try_into()
                    .map_err(|_| Error::Corruption("bad seq value in index CF".into()))?;
                Ok(Some(u64::from_be_bytes(bytes)))
            }
            None => Ok(None),
        }
    }

    /// Returns all entries with seq in `[start, end)`.
    pub fn seq_range(&self, start: u64, end: u64) -> Result<Vec<LogEntry>> {
        let cf = self.0.db.cf_handle(CF_LOG).expect("log CF must exist");
        let start_bytes = start.to_be_bytes();
        let iter = self
            .0
            .db
            .iterator_cf(cf, IteratorMode::From(&start_bytes, Direction::Forward));
        let mut entries = Vec::new();
        for item in iter {
            let (k, v) = item?;
            let seq = u64::from_be_bytes(
                k.as_ref()
                    .try_into()
                    .map_err(|_| Error::Corruption("bad seq key length".into()))?,
            );
            if seq >= end {
                break;
            }
            let proto = LogEntryProto::decode(v.as_ref())?;
            entries.push(LogEntry::try_from(proto)?);
        }
        Ok(entries)
    }

    /// Returns the most-recent `n` entries in newest-first order.
    /// `entries[0]` is the newest durably-stored entry.
    ///
    /// Reads strictly from durable storage (RocksDB reverse iteration), so it
    /// is not affected by the race where `next_seq` has been incremented by a
    /// concurrent `append` that has not yet committed its WriteBatch.
    pub fn latest(&self, n: usize) -> Result<Vec<LogEntry>> {
        if n == 0 {
            return Ok(Vec::new());
        }
        let cf = self.0.db.cf_handle(CF_LOG).expect("log CF must exist");
        let iter = self.0.db.iterator_cf(cf, IteratorMode::End);
        let mut entries = Vec::with_capacity(n);
        for item in iter {
            let (_k, v) = item?;
            let proto = LogEntryProto::decode(v.as_ref())?;
            entries.push(LogEntry::try_from(proto)?);
            if entries.len() >= n {
                break;
            }
        }
        Ok(entries)
    }
}

#[cfg(test)]
mod tests {
    use crate::db::Db;
    use tempfile::TempDir;

    fn open_fresh() -> (TempDir, Db) {
        let dir = TempDir::new().unwrap();
        let db = Db::open(dir.path()).unwrap();
        (dir, db)
    }

    #[test]
    fn written_entry_is_retrievable_by_seq() {
        let (_dir, db) = open_fresh();
        let log = db.log_store();
        let (seq, _) = log.append(b"k1", b"hello world").unwrap();
        let entry = log.get_by_seq(seq).unwrap().unwrap();
        assert_eq!(entry.seq, seq);
        assert_eq!(entry.key, b"k1");
        assert_eq!(entry.data, b"hello world");
        assert_eq!(entry.leaf_hash, settled_core::hash::leaf_hash(b"hello world"));
    }

    #[test]
    fn entry_survives_close_and_reopen() {
        let dir = TempDir::new().unwrap();
        let seq = {
            let db = Db::open(dir.path()).unwrap();
            let log = db.log_store();
            let (seq, _) = log.append(b"mykey", b"mydata").unwrap();
            seq
        };
        // DB is dropped / closed here.
        let db2 = Db::open(dir.path()).unwrap();
        let log2 = db2.log_store();
        let entry = log2.get_by_seq(seq).unwrap().unwrap();
        assert_eq!(entry.key, b"mykey");
        assert_eq!(entry.data, b"mydata");
    }

    #[test]
    fn index_survives_close_and_reopen() {
        let dir = TempDir::new().unwrap();
        let seq = {
            let db = Db::open(dir.path()).unwrap();
            let (seq, _) = db.log_store().append(b"lookup-key", b"data").unwrap();
            seq
        };
        let db2 = Db::open(dir.path()).unwrap();
        let found_seq = db2.log_store().get_seq_by_key(b"lookup-key").unwrap().unwrap();
        assert_eq!(found_seq, seq);
    }

    #[test]
    fn seq_range_returns_entries_in_order() {
        let (_dir, db) = open_fresh();
        let log = db.log_store();
        for i in 0u64..10 {
            log.append(format!("k{i}").as_bytes(), format!("d{i}").as_bytes())
                .unwrap();
        }
        let entries = log.seq_range(3, 7).unwrap();
        assert_eq!(entries.len(), 4);
        assert_eq!(entries[0].seq, 3);
        assert_eq!(entries[3].seq, 6);
    }

    #[test]
    fn latest_returns_empty_for_empty_log() {
        let (_dir, db) = open_fresh();
        let log = db.log_store();
        assert!(log.latest(5).unwrap().is_empty());
    }

    #[test]
    fn latest_returns_zero_for_n_zero() {
        let (_dir, db) = open_fresh();
        let log = db.log_store();
        log.append(b"k", b"v").unwrap();
        assert!(log.latest(0).unwrap().is_empty());
    }

    #[test]
    fn latest_returns_newest_first_and_caps_at_n() {
        let (_dir, db) = open_fresh();
        let log = db.log_store();
        for i in 0u64..10 {
            log.append(format!("k{i}").as_bytes(), format!("d{i}").as_bytes())
                .unwrap();
        }
        let entries = log.latest(3).unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].seq, 9);
        assert_eq!(entries[1].seq, 8);
        assert_eq!(entries[2].seq, 7);
        assert_eq!(entries[0].data, b"d9");
    }

    #[test]
    fn latest_returns_all_when_n_exceeds_log_size() {
        let (_dir, db) = open_fresh();
        let log = db.log_store();
        for i in 0u64..3 {
            log.append(format!("k{i}").as_bytes(), format!("d{i}").as_bytes())
                .unwrap();
        }
        let entries = log.latest(100).unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].seq, 2);
        assert_eq!(entries[2].seq, 0);
    }

    #[test]
    fn concurrent_appends_are_gap_free() {
        let (_dir, db) = open_fresh();
        let log = db.log_store();
        let n_threads = 8;
        let n_per_thread = 100usize;

        let handles: Vec<_> = (0..n_threads)
            .map(|t| {
                let log = log.clone();
                std::thread::spawn(move || {
                    for i in 0..n_per_thread {
                        let k = format!("t{t}-{i}");
                        log.append(k.as_bytes(), k.as_bytes()).unwrap();
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }

        let entries = log.seq_range(0, (n_threads * n_per_thread) as u64).unwrap();
        assert_eq!(entries.len(), n_threads * n_per_thread);

        let mut seqs: Vec<u64> = entries.iter().map(|e| e.seq).collect();
        seqs.sort_unstable();
        assert_eq!(seqs[0], 0);
        assert_eq!(*seqs.last().unwrap(), (n_threads * n_per_thread - 1) as u64);
        // All values are unique (no gaps).
        for w in seqs.windows(2) {
            assert_eq!(w[1], w[0] + 1);
        }
    }
}
