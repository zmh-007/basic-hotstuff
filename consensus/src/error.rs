use crate::consensus::View;
use crypto::{Digest, PublicKey};
use network::P2pError;
use store::StoreError;
use thiserror::Error;

#[macro_export]
macro_rules! bail {
    ($e:expr) => {
        return Err($e);
    };
}

#[macro_export(local_inner_macros)]
macro_rules! ensure {
    ($cond:expr, $e:expr) => {
        if !($cond) {
            bail!($e);
        }
    };
}

pub type ConsensusResult<T> = Result<T, ConsensusError>;

#[derive(Error, Debug)]
pub enum ConsensusError {
    #[error("Network error: {0}")]
    NetworkError(#[from] std::io::Error),

    #[error("P2P network error: {0}")]
    P2pNetworkError(#[from] P2pError),

    #[error("Serialization error: {0}")]
    SerializationError(#[from] Box<bincode::ErrorKind>),

    #[error("Store error: {0}")]
    StoreError(#[from] StoreError),

    #[error("Node {0} is not in the committee")]
    NotInCommittee(String),

    #[error("Invalid signature from {0}")]
    InvalidSignature(String),

    #[error("Received more than one vote from {0}")]
    AuthorityReuse(PublicKey),

    #[error("Received vote from unknown authority {0}")]
    UnknownAuthority(PublicKey),

    #[error("Received QC without a quorum")]
    QCRequiresQuorum,

    #[error("Wrong leader: received block {digest} from {leader} at view {view}")]
    WrongLeader {
        digest: Digest,
        leader: PublicKey,
        view: View,
    },

    #[error("Invalid payload")]
    InvalidPayload,

    #[error("Invalid QC: {0}")]
    InvalidQC(String),

    #[error("Safe node violation: {0}")]
    SafeNodeViolation(String),

    #[error("invalid aggregated public key")]
    InvalidAggregatedPublicKey,
}
