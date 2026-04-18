use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("RocksDB error: {0}")]
    RocksDb(#[from] rocksdb::Error),
    #[error("Protobuf encode error: {0}")]
    Encode(#[from] prost::EncodeError),
    #[error("Protobuf decode error: {0}")]
    Decode(#[from] prost::DecodeError),
    #[error("Data corruption: {0}")]
    Corruption(String),
    #[error("Schema version mismatch: found {found}, this binary supports up to {supported}")]
    SchemaMismatch { found: u32, supported: u32 },
}

pub type Result<T> = std::result::Result<T, Error>;
