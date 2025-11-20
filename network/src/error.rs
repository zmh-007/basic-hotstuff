#[derive(Debug, Clone)]
pub enum P2pError {
    AlreadyInitialized,
    NotInitialized,
    ChannelClosed,
    InvalidPrivateKey(String),
    KeypairGeneration(String),
    PeerNotConnected(String),
    NoPeersAvailable,
}

impl std::fmt::Display for P2pError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            P2pError::AlreadyInitialized => write!(f, "P2P node already initialized"),
            P2pError::NotInitialized => write!(f, "P2P node not initialized"),
            P2pError::ChannelClosed => write!(f, "Message channel closed"),
            P2pError::InvalidPrivateKey(msg) => write!(f, "Invalid private key: {}", msg),
            P2pError::KeypairGeneration(msg) => write!(f, "Failed to generate keypair: {}", msg),
            P2pError::PeerNotConnected(peer) => write!(f, "Peer {} not connected", peer),
            P2pError::NoPeersAvailable => write!(f, "No peers available for broadcasting"),
        }
    }
}

impl std::error::Error for P2pError {}

pub type P2pResult<T> = Result<T, P2pError>;