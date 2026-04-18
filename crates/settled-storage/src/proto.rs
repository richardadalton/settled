/// Internal protobuf message types. Not part of the public API.
/// Use the types in `types.rs` instead.

#[derive(Clone, PartialEq, prost::Message)]
pub(crate) struct CounterSignatureProto {
    #[prost(string, tag = "1")]
    pub settled_node_url: String,
    #[prost(bytes = "vec", tag = "2")]
    pub public_key: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub signature: Vec<u8>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub(crate) struct FinalSTHProto {
    #[prost(message, tag = "1")]
    pub sth: Option<SignedTreeHeadProto>,
    #[prost(message, repeated, tag = "2")]
    pub counter_signatures: Vec<CounterSignatureProto>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub(crate) struct LogEntryProto {
    #[prost(uint64, tag = "1")]
    pub seq: u64,
    #[prost(int64, tag = "2")]
    pub timestamp_ns: i64,
    #[prost(bytes = "vec", tag = "3")]
    pub key: Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    pub data: Vec<u8>,
    #[prost(bytes = "vec", tag = "5")]
    pub leaf_hash: Vec<u8>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub(crate) struct SignedTreeHeadProto {
    #[prost(uint64, tag = "1")]
    pub tree_size: u64,
    #[prost(bytes = "vec", tag = "2")]
    pub root_hash: Vec<u8>,
    #[prost(int64, tag = "3")]
    pub timestamp_ns: i64,
    #[prost(bytes = "vec", tag = "4")]
    pub signature: Vec<u8>,
    #[prost(bytes = "vec", tag = "5")]
    pub public_key: Vec<u8>,
    #[prost(uint32, tag = "6")]
    pub key_version: u32,
}
