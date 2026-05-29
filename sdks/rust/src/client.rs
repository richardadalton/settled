use tonic::metadata::MetadataValue;
use tonic::transport::Channel;
use tonic::Request;

mod proto {
    tonic::include_proto!("settled.v1");
}

use proto::settled_log_client::SettledLogClient;

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("invalid address: {0}")]
    InvalidAddress(String),
    #[error("transport error: {0}")]
    Transport(#[from] tonic::transport::Error),
    #[error("rpc error: {0}")]
    Rpc(#[from] tonic::Status),
}

#[derive(Debug, Clone)]
pub struct SignedTreeHead {
    pub tree_size: u64,
    pub root_hash: Vec<u8>,
    pub timestamp_ns: i64,
    pub signature: Vec<u8>,
    pub public_key: Vec<u8>,
    pub key_version: u32,
}

#[derive(Debug, Clone)]
pub struct AppendResult {
    pub seq: u64,
    pub timestamp_ns: i64,
    pub leaf_hash: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct Entry {
    pub seq: u64,
    pub timestamp_ns: i64,
    pub key: Vec<u8>,
    pub data: Vec<u8>,
    pub leaf_hash: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct InclusionProofResult {
    pub leaf_index: u64,
    pub tree_size: u64,
    pub proof: Vec<Vec<u8>>,
    pub sth: SignedTreeHead,
}

#[derive(Debug, Clone)]
pub struct ConsistencyProofResult {
    pub old_size: u64,
    pub new_size: u64,
    pub proof: Vec<Vec<u8>>,
    pub old_sth: SignedTreeHead,
    pub new_sth: SignedTreeHead,
}

#[derive(Debug, Clone)]
pub struct GetLatestResult {
    pub entries: Vec<Entry>,
    /// Total entries durably stored in the log. If greater than `entries.len()`
    /// the response was capped; use `list_entries` to page through older ones.
    pub total_available: u64,
}

#[derive(Debug, Clone)]
pub struct ListEntriesResult {
    pub entries: Vec<Entry>,
    /// Pass as `cursor` in the next call. `0` means no more pages.
    pub next_cursor: u64,
}

#[derive(Debug, Clone)]
pub struct GetByKeyResult {
    pub entries: Vec<Entry>,
    /// Pass as `cursor` in the next call. `0` means no more pages.
    pub next_cursor: u64,
}

/// A live stream of entries returned by `watch_entries`.
///
/// Call `.next().await` in a loop; returns `None` when the stream ends.
pub struct EntryStream {
    inner: tonic::Streaming<proto::Entry>,
}

impl EntryStream {
    pub async fn next(&mut self) -> Option<Result<Entry, ClientError>> {
        match self.inner.message().await {
            Ok(Some(e)) => Some(Ok(from_pb_entry(e))),
            Ok(None) => None,
            Err(e) => Some(Err(ClientError::Rpc(e))),
        }
    }
}

fn from_pb_sth(s: proto::SignedTreeHead) -> SignedTreeHead {
    SignedTreeHead {
        tree_size: s.tree_size,
        root_hash: s.root_hash,
        timestamp_ns: s.timestamp_ns,
        signature: s.signature,
        public_key: s.public_key,
        key_version: s.key_version,
    }
}

fn from_pb_entry(e: proto::Entry) -> Entry {
    Entry {
        seq: e.seq,
        timestamp_ns: e.timestamp_ns,
        key: e.key,
        data: e.data,
        leaf_hash: e.leaf_hash,
    }
}

/// Async gRPC client for SettledLog.
pub struct SettledClient {
    inner: SettledLogClient<Channel>,
    auth_header: Option<MetadataValue<tonic::metadata::Ascii>>,
}

impl SettledClient {
    /// Connect to the server at `addr` (e.g. `"http://localhost:50051"`).
    pub async fn connect(addr: impl Into<String>) -> Result<Self, ClientError> {
        Self::build(addr, None).await
    }

    /// Connect with an API key sent as `authorization: Bearer <key>` on every request.
    pub async fn connect_with_api_key(
        addr: impl Into<String>,
        api_key: impl Into<String>,
    ) -> Result<Self, ClientError> {
        Self::build(addr, Some(api_key.into())).await
    }

    async fn build(addr: impl Into<String>, api_key: Option<String>) -> Result<Self, ClientError> {
        let addr = addr.into();
        let channel = Channel::from_shared(addr.clone())
            .map_err(|_| ClientError::InvalidAddress(addr))?
            .connect()
            .await?;
        let auth_header = api_key.map(|k| {
            MetadataValue::try_from(format!("Bearer {k}")).expect("api key must be valid ASCII")
        });
        Ok(Self {
            inner: SettledLogClient::new(channel),
            auth_header,
        })
    }

    fn make_request<T>(&self, body: T) -> Request<T> {
        let mut req = Request::new(body);
        if let Some(ref val) = self.auth_header {
            req.metadata_mut().insert("authorization", val.clone());
        }
        req
    }

    /// Append an entry and return its sequence number, timestamp, and leaf hash.
    pub async fn append(
        &mut self,
        key: Vec<u8>,
        data: Vec<u8>,
    ) -> Result<AppendResult, ClientError> {
        let r = self
            .inner
            .append(self.make_request(proto::AppendRequest { key, data }))
            .await?
            .into_inner();
        Ok(AppendResult {
            seq: r.seq,
            timestamp_ns: r.timestamp_ns,
            leaf_hash: r.leaf_hash,
        })
    }

    /// Retrieve a log entry by sequence number.
    pub async fn get(&mut self, seq: u64) -> Result<Entry, ClientError> {
        let r = self
            .inner
            .get(self.make_request(proto::GetRequest { seq }))
            .await?
            .into_inner();
        Ok(from_pb_entry(r.entry.unwrap_or_default()))
    }

    /// Retrieve the most-recent `n` entries (newest first). `n=0` is treated as 1.
    /// Values above the server cap (1000) are silently clamped; check
    /// `total_available` to determine whether the result was truncated.
    pub async fn get_latest(&mut self, n: u32) -> Result<GetLatestResult, ClientError> {
        let r = self
            .inner
            .get_latest(self.make_request(proto::GetLatestRequest { n }))
            .await?
            .into_inner();
        Ok(GetLatestResult {
            entries: r.entries.into_iter().map(from_pb_entry).collect(),
            total_available: r.total_available,
        })
    }

    /// Retrieve a Signed Tree Head. Pass `tree_size=0` for the latest.
    pub async fn get_sth(&mut self, tree_size: u64) -> Result<SignedTreeHead, ClientError> {
        let r = self
            .inner
            .get_sth(self.make_request(proto::GetSthRequest { tree_size }))
            .await?
            .into_inner();
        Ok(from_pb_sth(r.sth.unwrap_or_default()))
    }

    /// Return an inclusion proof for `seq` against `tree_size`. Pass `tree_size=0` for the latest STH.
    pub async fn inclusion_proof(
        &mut self,
        seq: u64,
        tree_size: u64,
    ) -> Result<InclusionProofResult, ClientError> {
        let r = self
            .inner
            .inclusion_proof(self.make_request(proto::InclusionProofRequest { seq, tree_size }))
            .await?
            .into_inner();
        Ok(InclusionProofResult {
            leaf_index: r.leaf_index,
            tree_size: r.tree_size,
            proof: r.proof,
            sth: from_pb_sth(r.sth.unwrap_or_default()),
        })
    }

    /// Open a server-streaming Watch RPC.
    ///
    /// `from_seq > 0`: replays entries starting at that seq, then continues live.
    /// `from_seq == 0`: streams only entries appended after the call returns.
    ///
    /// Call `.next().await` on the returned [`EntryStream`] in a loop.
    /// Returns `None` when the stream ends (server closed it or cancelled).
    pub async fn watch_entries(&mut self, from_seq: u64) -> Result<EntryStream, ClientError> {
        let stream = self
            .inner
            .watch(self.make_request(proto::WatchRequest { from_seq }))
            .await?
            .into_inner();
        Ok(EntryStream { inner: stream })
    }

    /// Retrieve a page of entries in seq order within `[from_seq, to_seq)`.
    /// `to_seq = 0` scans to the end of the log. Pass `cursor = 0` to start
    /// from `from_seq`; pass `next_cursor` from the previous response to page.
    /// `limit = 0` uses the server default (50).
    pub async fn list_entries(
        &mut self,
        from_seq: u64,
        to_seq: u64,
        cursor: u64,
        limit: u32,
    ) -> Result<ListEntriesResult, ClientError> {
        let r = self
            .inner
            .list_entries(self.make_request(proto::ListEntriesRequest {
                from_seq,
                to_seq,
                cursor,
                limit,
            }))
            .await?
            .into_inner();
        Ok(ListEntriesResult {
            entries: r.entries.into_iter().map(from_pb_entry).collect(),
            next_cursor: r.next_cursor,
        })
    }

    /// Retrieve all entries for a given key with cursor-based pagination.
    /// Pass `cursor=0` to start from the beginning. `next_cursor=0` in the
    /// result means no further pages exist. `limit=0` uses the server default.
    pub async fn get_by_key(
        &mut self,
        key: Vec<u8>,
        cursor: u64,
        limit: u32,
    ) -> Result<GetByKeyResult, ClientError> {
        let r = self
            .inner
            .get_by_key(self.make_request(proto::GetByKeyRequest { key, cursor, limit }))
            .await?
            .into_inner();
        Ok(GetByKeyResult {
            entries: r.entries.into_iter().map(from_pb_entry).collect(),
            next_cursor: r.next_cursor,
        })
    }

    /// Return a consistency proof between `old_size` and `new_size`. Pass `new_size=0` for the latest STH.
    pub async fn consistency_proof(
        &mut self,
        old_size: u64,
        new_size: u64,
    ) -> Result<ConsistencyProofResult, ClientError> {
        let r = self
            .inner
            .consistency_proof(
                self.make_request(proto::ConsistencyProofRequest { old_size, new_size }),
            )
            .await?
            .into_inner();
        Ok(ConsistencyProofResult {
            old_size: r.old_size,
            new_size: r.new_size,
            proof: r.proof,
            old_sth: from_pb_sth(r.old_sth.unwrap_or_default()),
            new_sth: from_pb_sth(r.new_sth.unwrap_or_default()),
        })
    }
}
