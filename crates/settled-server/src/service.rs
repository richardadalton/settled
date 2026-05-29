use std::pin::Pin;

use settled_core::{hash::leaf_hash, proof};
use settled_storage::SignedTreeHead;
use tokio::sync::broadcast;
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::Stream;
use tonic::{Request, Response, Status};

use crate::error::Error;
use crate::proto::settled_log_server::SettledLog;
use crate::proto::{
    AppendRequest, AppendResponse, ConsistencyProofRequest, ConsistencyProofResponse, Entry,
    GetByKeyRequest, GetByKeyResponse, GetLatestRequest, GetLatestResponse, GetRequest,
    GetResponse, GetSthRequest, GetSthResponse, InclusionProofRequest, InclusionProofResponse,
    ListEntriesRequest, ListEntriesResponse, SignedTreeHead as ProtoSth, WatchRequest,
};
use crate::state::AppState;

/// Maximum number of entries returnable by a single GetLatest call.
/// Larger values are silently clamped to this cap.
const MAX_LATEST: u32 = 1000;

/// Maximum number of entries returnable by a single GetByKey call.
const MAX_BY_KEY: u32 = 1000;
/// Default page size for GetByKey when limit == 0.
const DEFAULT_BY_KEY: u32 = 50;

/// Maximum number of entries returnable by a single ListEntries call.
const MAX_LIST: u32 = 1000;
/// Default page size for ListEntries when limit == 0.
const DEFAULT_LIST: u32 = 50;

pub struct SettledService {
    state: AppState,
}

impl SettledService {
    pub fn new(state: AppState) -> Self {
        Self { state }
    }
}

fn sth_to_proto(s: SignedTreeHead) -> ProtoSth {
    ProtoSth {
        tree_size: s.tree_size,
        root_hash: s.root_hash.to_vec(),
        timestamp_ns: s.timestamp_ns,
        signature: s.signature.to_vec(),
        public_key: s.public_key.to_vec(),
        key_version: s.key_version,
    }
}

#[tonic::async_trait]
impl SettledLog for SettledService {
    type WatchStream = Pin<Box<dyn Stream<Item = Result<Entry, Status>> + Send + 'static>>;
    async fn append(
        &self,
        request: Request<AppendRequest>,
    ) -> Result<Response<AppendResponse>, Status> {
        let req = request.into_inner();
        let lh = leaf_hash(&req.data);

        let timer = crate::metrics::APPEND_DURATION.start_timer();
        let (seq, timestamp_ns) = {
            let mut mu = self.state.append_mu.lock().unwrap();
            let (seq, ts) = self
                .state
                .log
                .append(&req.key, &req.data)
                .map_err(|e| Status::from(Error::Storage(e)))?;
            mu.merkle.append(lh);
            (seq, ts)
        };
        timer.observe_duration();
        crate::metrics::ENTRIES_APPENDED.inc();

        tracing::debug!(seq, "appended entry");

        // Notify Watch subscribers. Ignore the error when there are no receivers.
        let _ = self.state.watch_tx.send(Entry {
            seq,
            timestamp_ns,
            key: req.key,
            data: req.data,
            leaf_hash: lh.to_vec(),
        });

        Ok(Response::new(AppendResponse {
            seq,
            timestamp_ns,
            leaf_hash: lh.to_vec(),
        }))
    }

    async fn get(&self, request: Request<GetRequest>) -> Result<Response<GetResponse>, Status> {
        let req = request.into_inner();

        let entry = self
            .state
            .log
            .get_by_seq(req.seq)
            .map_err(|e| Status::from(Error::Storage(e)))?
            .ok_or_else(|| Status::from(Error::NotFound(format!("seq {} not found", req.seq))))?;

        Ok(Response::new(GetResponse {
            entry: Some(Entry {
                seq: entry.seq,
                timestamp_ns: entry.timestamp_ns,
                key: entry.key,
                data: entry.data,
                leaf_hash: entry.leaf_hash.to_vec(),
            }),
        }))
    }

    async fn get_latest(
        &self,
        request: Request<GetLatestRequest>,
    ) -> Result<Response<GetLatestResponse>, Status> {
        let req = request.into_inner();
        let n = if req.n == 0 { 1 } else { req.n.min(MAX_LATEST) } as usize;

        let log = self.state.log.clone();
        let entries = tokio::task::spawn_blocking(move || log.latest(n))
            .await
            .map_err(|e| Status::internal(e.to_string()))?
            .map_err(|e| Status::from(Error::Storage(e)))?;

        let entries = entries
            .into_iter()
            .map(|e| Entry {
                seq: e.seq,
                timestamp_ns: e.timestamp_ns,
                key: e.key,
                data: e.data,
                leaf_hash: e.leaf_hash.to_vec(),
            })
            .collect();

        Ok(Response::new(GetLatestResponse { entries }))
    }

    async fn watch(
        &self,
        request: Request<WatchRequest>,
    ) -> Result<Response<Self::WatchStream>, Status> {
        let from_seq = request.into_inner().from_seq;

        // Subscribe BEFORE reading history so we don't miss entries appended
        // while the replay is in flight.
        let mut watch_rx = self.state.watch_tx.subscribe();
        let log = self.state.log.clone();

        let (tx, rx) = tokio::sync::mpsc::channel::<Result<Entry, Status>>(128);

        tokio::spawn(async move {
            let mut last_sent: Option<u64> = None;

            // Phase 1: replay history when from_seq > 0
            if from_seq > 0 {
                let mut cursor = from_seq;
                'replay: loop {
                    let log2 = log.clone();
                    let result =
                        tokio::task::spawn_blocking(move || log2.seq_range_paged(cursor, 0, 200))
                            .await;
                    let (entries, next) = match result {
                        Ok(Ok(r)) => r,
                        Ok(Err(e)) => {
                            let _ = tx.send(Err(Status::internal(e.to_string()))).await;
                            return;
                        }
                        Err(e) => {
                            let _ = tx.send(Err(Status::internal(e.to_string()))).await;
                            return;
                        }
                    };
                    for entry in entries {
                        let seq = entry.seq;
                        let proto_entry = Entry {
                            seq: entry.seq,
                            timestamp_ns: entry.timestamp_ns,
                            key: entry.key,
                            data: entry.data,
                            leaf_hash: entry.leaf_hash.to_vec(),
                        };
                        if tx.send(Ok(proto_entry)).await.is_err() {
                            return;
                        }
                        last_sent = Some(seq);
                    }
                    if next == 0 {
                        break 'replay;
                    }
                    cursor = next;
                }
            }

            // Phase 2: live stream, skipping entries already sent during replay
            loop {
                match watch_rx.recv().await {
                    Ok(entry) => {
                        if last_sent.map_or(false, |last| entry.seq <= last) {
                            continue;
                        }
                        last_sent = Some(entry.seq);
                        if tx.send(Ok(entry)).await.is_err() {
                            return;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!(lagged = n, "Watch stream fell behind broadcast channel");
                        let _ = tx
                            .send(Err(Status::resource_exhausted(format!(
                                "stream lagged by {n} entries; reconnect with last seen seq"
                            ))))
                            .await;
                        return;
                    }
                    Err(broadcast::error::RecvError::Closed) => return,
                }
            }
        });

        Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
    }

    async fn list_entries(
        &self,
        request: Request<ListEntriesRequest>,
    ) -> Result<Response<ListEntriesResponse>, Status> {
        let req = request.into_inner();
        let limit = if req.limit == 0 {
            DEFAULT_LIST
        } else {
            req.limit.min(MAX_LIST)
        } as usize;
        let start = if req.cursor > 0 {
            req.cursor
        } else {
            req.from_seq
        };

        let log = self.state.log.clone();
        let to_seq = req.to_seq;
        let (entries, next_cursor) =
            tokio::task::spawn_blocking(move || log.seq_range_paged(start, to_seq, limit))
                .await
                .map_err(|e| Status::internal(e.to_string()))?
                .map_err(|e| Status::from(Error::Storage(e)))?;

        let entries = entries
            .into_iter()
            .map(|e| Entry {
                seq: e.seq,
                timestamp_ns: e.timestamp_ns,
                key: e.key,
                data: e.data,
                leaf_hash: e.leaf_hash.to_vec(),
            })
            .collect();

        Ok(Response::new(ListEntriesResponse {
            entries,
            next_cursor,
        }))
    }

    async fn get_by_key(
        &self,
        request: Request<GetByKeyRequest>,
    ) -> Result<Response<GetByKeyResponse>, Status> {
        let req = request.into_inner();
        if req.key.is_empty() {
            return Err(Status::from(Error::InvalidArgument(
                "key must not be empty".into(),
            )));
        }
        let limit = if req.limit == 0 {
            DEFAULT_BY_KEY
        } else {
            req.limit.min(MAX_BY_KEY)
        } as usize;

        let key = req.key;
        let from_seq = req.cursor;
        let log = self.state.log.clone();
        let (entries, next_cursor) =
            tokio::task::spawn_blocking(move || log.entries_by_key(&key, from_seq, limit))
                .await
                .map_err(|e| Status::internal(e.to_string()))?
                .map_err(|e| Status::from(Error::Storage(e)))?;

        let entries = entries
            .into_iter()
            .map(|e| Entry {
                seq: e.seq,
                timestamp_ns: e.timestamp_ns,
                key: e.key,
                data: e.data,
                leaf_hash: e.leaf_hash.to_vec(),
            })
            .collect();

        Ok(Response::new(GetByKeyResponse {
            entries,
            next_cursor,
        }))
    }

    async fn get_sth(
        &self,
        request: Request<GetSthRequest>,
    ) -> Result<Response<GetSthResponse>, Status> {
        let req = request.into_inner();

        let sth = if req.tree_size == 0 {
            self.state
                .heads
                .latest()
                .map_err(|e| Status::from(Error::Storage(e)))?
                .ok_or_else(|| Status::from(Error::NotFound("no STH available yet".into())))?
        } else {
            self.state
                .heads
                .at_size(req.tree_size)
                .map_err(|e| Status::from(Error::Storage(e)))?
                .ok_or_else(|| {
                    Status::from(Error::NotFound(format!(
                        "no STH at tree_size {}",
                        req.tree_size
                    )))
                })?
        };

        Ok(Response::new(GetSthResponse {
            sth: Some(sth_to_proto(sth)),
        }))
    }

    async fn inclusion_proof(
        &self,
        request: Request<InclusionProofRequest>,
    ) -> Result<Response<InclusionProofResponse>, Status> {
        let req = request.into_inner();

        let tree_size = if req.tree_size == 0 {
            self.state
                .heads
                .latest()
                .map_err(|e| Status::from(Error::Storage(e)))?
                .ok_or_else(|| Status::from(Error::NotFound("no STH available yet".into())))?
                .tree_size
        } else {
            req.tree_size
        };

        if req.seq >= tree_size {
            return Err(Status::from(Error::InvalidArgument(format!(
                "seq {} is out of range for tree_size {}",
                req.seq, tree_size
            ))));
        }

        let log = self.state.log.clone();
        let leaf_hashes: Vec<[u8; 32]> = tokio::task::spawn_blocking(move || {
            log.seq_range(0, tree_size)
                .map(|entries| entries.iter().map(|e| e.leaf_hash).collect())
        })
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .map_err(|e| Status::from(Error::Storage(e)))?;

        let path = proof::inclusion_proof(&leaf_hashes, req.seq as usize)
            .map_err(|e| Status::from(Error::Proof(e)))?;

        let sth = self
            .state
            .heads
            .at_size(tree_size)
            .map_err(|e| Status::from(Error::Storage(e)))?
            .ok_or_else(|| {
                Status::from(Error::NotFound(format!("no STH at tree_size {tree_size}")))
            })?;

        Ok(Response::new(InclusionProofResponse {
            leaf_index: req.seq,
            tree_size,
            proof: path.iter().map(|h| h.to_vec()).collect(),
            sth: Some(sth_to_proto(sth)),
        }))
    }

    async fn consistency_proof(
        &self,
        request: Request<ConsistencyProofRequest>,
    ) -> Result<Response<ConsistencyProofResponse>, Status> {
        let req = request.into_inner();

        if req.old_size == 0 {
            return Err(Status::from(Error::InvalidArgument(
                "old_size must be > 0".into(),
            )));
        }

        let new_size = if req.new_size == 0 {
            self.state
                .heads
                .latest()
                .map_err(|e| Status::from(Error::Storage(e)))?
                .ok_or_else(|| Status::from(Error::NotFound("no STH available yet".into())))?
                .tree_size
        } else {
            req.new_size
        };

        if req.old_size > new_size {
            return Err(Status::from(Error::InvalidArgument(format!(
                "old_size {} > new_size {}",
                req.old_size, new_size
            ))));
        }

        let old_size = req.old_size;
        let log = self.state.log.clone();
        let leaf_hashes: Vec<[u8; 32]> = tokio::task::spawn_blocking(move || {
            log.seq_range(0, new_size)
                .map(|entries| entries.iter().map(|e| e.leaf_hash).collect())
        })
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .map_err(|e| Status::from(Error::Storage(e)))?;

        let path = proof::consistency_proof(&leaf_hashes, old_size as usize)
            .map_err(|e| Status::from(Error::Proof(e)))?;

        let old_sth = self
            .state
            .heads
            .at_size(old_size)
            .map_err(|e| Status::from(Error::Storage(e)))?
            .ok_or_else(|| {
                Status::from(Error::NotFound(format!("no STH at old_size {old_size}")))
            })?;

        let new_sth = self
            .state
            .heads
            .at_size(new_size)
            .map_err(|e| Status::from(Error::Storage(e)))?
            .ok_or_else(|| {
                Status::from(Error::NotFound(format!("no STH at new_size {new_size}")))
            })?;

        Ok(Response::new(ConsistencyProofResponse {
            old_size,
            new_size,
            proof: path.iter().map(|h| h.to_vec()).collect(),
            old_sth: Some(sth_to_proto(old_sth)),
            new_sth: Some(sth_to_proto(new_sth)),
        }))
    }
}
