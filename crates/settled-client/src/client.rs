use tonic::transport::Channel;
use tonic::Request;

pub mod proto {
    tonic::include_proto!("settled.v1");
}

use proto::settled_log_client::SettledLogClient;
pub use proto::{
    AppendRequest, AppendResponse, ConsistencyProofRequest, ConsistencyProofResponse,
    GetLatestRequest, GetLatestResponse, GetRequest, GetResponse, GetSthRequest, GetSthResponse,
    InclusionProofRequest, InclusionProofResponse, SignedTreeHead,
};

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("transport error: {0}")]
    Transport(#[from] tonic::transport::Error),
    #[error("rpc error: {0}")]
    Rpc(#[from] tonic::Status),
}

/// Async gRPC client for SettledLog.
pub struct SettledClient {
    inner: SettledLogClient<Channel>,
}

impl SettledClient {
    /// Connect to the server at `addr` (e.g. `"http://localhost:9000"`).
    pub async fn connect(addr: impl Into<String>) -> Result<Self, ClientError> {
        let channel = Channel::from_shared(addr.into())
            .expect("invalid uri")
            .connect()
            .await?;
        Ok(Self { inner: SettledLogClient::new(channel) })
    }

    pub async fn append(&mut self, key: Vec<u8>, data: Vec<u8>) -> Result<AppendResponse, ClientError> {
        let res = self.inner.append(Request::new(AppendRequest { key, data })).await?;
        Ok(res.into_inner())
    }

    pub async fn get(&mut self, seq: u64) -> Result<GetResponse, ClientError> {
        let res = self.inner.get(Request::new(GetRequest { seq })).await?;
        Ok(res.into_inner())
    }

    /// Fetch the most-recent `n` entries (newest first). Pass `n = 0` for the
    /// single most-recent entry; values above the server cap are clamped.
    pub async fn get_latest(&mut self, n: u32) -> Result<GetLatestResponse, ClientError> {
        let res = self.inner.get_latest(Request::new(GetLatestRequest { n })).await?;
        Ok(res.into_inner())
    }

    /// Pass `tree_size = 0` to get the latest STH.
    pub async fn get_sth(&mut self, tree_size: u64) -> Result<GetSthResponse, ClientError> {
        let res = self.inner.get_sth(Request::new(GetSthRequest { tree_size })).await?;
        Ok(res.into_inner())
    }

    /// Pass `tree_size = 0` to use the latest STH.
    pub async fn inclusion_proof(&mut self, seq: u64, tree_size: u64) -> Result<InclusionProofResponse, ClientError> {
        let res = self.inner.inclusion_proof(Request::new(InclusionProofRequest { seq, tree_size })).await?;
        Ok(res.into_inner())
    }

    /// Pass `new_size = 0` to use the latest STH.
    pub async fn consistency_proof(&mut self, old_size: u64, new_size: u64) -> Result<ConsistencyProofResponse, ClientError> {
        let res = self.inner.consistency_proof(Request::new(ConsistencyProofRequest { old_size, new_size })).await?;
        Ok(res.into_inner())
    }
}
