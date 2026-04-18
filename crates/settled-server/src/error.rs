use tonic::Status;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("storage error: {0}")]
    Storage(#[from] settled_storage::Error),
    #[error("proof error: {0}")]
    Proof(#[from] settled_core::proof::ProofError),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
}

impl From<Error> for Status {
    fn from(e: Error) -> Self {
        match e {
            Error::NotFound(msg) => Status::not_found(msg),
            Error::InvalidArgument(msg) => Status::invalid_argument(msg),
            Error::Storage(e) => Status::internal(e.to_string()),
            Error::Proof(e) => Status::internal(e.to_string()),
        }
    }
}
