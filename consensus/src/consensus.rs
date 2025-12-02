// Core consensus imports
use crate::{
    config::{Committee, Parameters},
    core::Core,
    error::{ConsensusError, ConsensusResult},
    utils::verify_signature,
    LeaderElector,
};

// External crates
use blst::min_pk::AggregatePublicKey;
use crypto::{Digest, PublicKey, SignatureService, Signature};
use hex::decode;
use l0::Blk;
use libp2p::PeerId;
use log::{error, info};
use network::P2pLibp2p;
use replica::replica::ReplicaClient;
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, sync::Arc};
use store::Store;
use tokio::sync::mpsc::{self, Sender};
use zk::{AsBytes, Fr, ToHash};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
pub struct View {
    pub height: u64,
    pub round: u64,
}

impl View {
    pub fn default() -> Self {
        Self { height: 1, round: 0 }
    }

    pub fn digest(&self) -> Fr {
        let elements = vec![
            Fr::from(self.height),
            Fr::from(self.round),
        ];
        elements.hash()
    }
}

impl std::fmt::Display for View {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "View {{ height: {}, round: {} }}", self.height, self.round)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Copy)]
pub enum ConsensusMessageType {
    Prepare,
    PreCommit,
    Commit,
    Decide,
    NewView,
}

impl ConsensusMessageType {
    fn to_field(&self) -> Fr {
        match self {
            ConsensusMessageType::Prepare => Fr::from(0u64),
            ConsensusMessageType::PreCommit => Fr::from(1u64),
            ConsensusMessageType::Commit => Fr::from(2u64),
            ConsensusMessageType::Decide => Fr::from(3u64),
            ConsensusMessageType::NewView => Fr::from(4u64),
        }
    }
    pub fn to_string(&self) -> &'static str {
        match self {
            ConsensusMessageType::Prepare => "Prepare",
            ConsensusMessageType::PreCommit => "PreCommit",
            ConsensusMessageType::Commit => "Commit",
            ConsensusMessageType::Decide => "Decide",
            ConsensusMessageType::NewView => "NewView",
        }
    }
}

/// MessagePayload represents the different types of message content
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum MessagePayload {
    NewView(QuorumCert),
    Prepare(Node, QuorumCert),
    PrepareVote(Digest),
    PreCommit(QuorumCert),
    PreCommitVote(Digest),
    Commit(QuorumCert),
    CommitVote(Digest),
    Decide(QuorumCert, String),
}

impl MessagePayload {
    pub fn digest(&self) -> Digest {
        match self {
            Self::NewView(qc) | Self::PreCommit(qc) | Self::Commit(qc) | Self::Decide(qc, _) => {
                qc.digest()
            }
            Self::Prepare(node, qc) => {
                let elements = vec![node.digest().to_field(), qc.digest().to_field()];
                let bytes: Vec<u8> = elements.hash().enc().collect();
                Digest(bytes.try_into().unwrap_or([0u8; 32]))
            }
            Self::PrepareVote(digest) | Self::PreCommitVote(digest) | Self::CommitVote(digest) => {
                *digest
            }
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ConsensusMessage {
    pub msg_type: ConsensusMessageType,
    pub author: PublicKey,
    pub view: View,
    pub msg: MessagePayload,
    pub signature: Signature,
}

impl ConsensusMessage {
    pub fn digest(&self) -> Digest {
        let elements = vec![
            self.msg_type.to_field(),
            self.view.digest(),
            self.msg.digest().to_field(),
        ];
        let bytes: Vec<u8> = elements.hash().enc().collect();
        Digest(bytes.try_into().unwrap_or([0u8; 32]))
    }

    pub async fn new(
        msg_type: ConsensusMessageType,
        author: PublicKey,
        view: View,
        msg: MessagePayload,
        mut signature_service: SignatureService,
    ) -> Self {
        let message = Self {
            msg_type,
            author,
            view,
            msg,
            signature: Signature::default(),
        };
        
        let signature = signature_service.request_signature(message.digest()).await;
        Self { signature, ..message }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Node {
    pub parent: Digest,
    pub blob: String,
}

impl Node {
    pub fn default() -> Self {
        Self {
            parent: Digest::default(), // Genesis node has no parent
            blob: String::new(),
        }
    }

    pub fn digest(&self) -> Digest {
        let blob_digest = if self.blob.is_empty() {
            Fr::from(0u64)
        } else {
            match decode(&self.blob) {
                Ok(bytes) => {
                    match Blk::dec(&mut bytes.into_iter()) {
                        Ok(blk) => blk.hash(),
                        Err(_) => {
                            error!("Failed to decode block from blob: {}", self.blob);
                            Fr::from(0u64)
                        }
                    }
                }
                Err(_) => {
                    error!("Failed to decode hex blob: {}", self.blob);
                    Fr::from(0u64)
                }
            }
        };
        
        let elements = (self.parent.to_field(), blob_digest);
        let bytes: Vec<u8> = elements.hash().enc().collect();
        
        Digest(bytes.try_into().unwrap_or_else(|_| {
            error!("Failed to convert hash bytes to digest");
            [0u8; 32]
        }))
    }

    pub fn new(parent: Digest, blob: String) -> Self {
        Self {
            parent,
            blob,
        }
    }
}

/// QuorumCert represents a quorum certificate with signatures
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct QuorumCert {
    pub qc_type: ConsensusMessageType,
    pub view: View,
    pub node_digest: Digest,
    pub agg_sig: Signature,
    pub agg_pk: PublicKey,
    pub public_keys: Vec<PublicKey>,
}

impl PartialEq for QuorumCert {
    fn eq(&self, other: &Self) -> bool {
        self.qc_type == other.qc_type
            && self.view == other.view
            && self.node_digest == other.node_digest
    }
}

impl QuorumCert {
    pub fn default() -> Self {
        Self {
            qc_type: ConsensusMessageType::Prepare,
            view: View::default(),
            node_digest: Digest::default(),
            agg_sig: Signature::default(),
            agg_pk: PublicKey::default(),
            public_keys: Vec::new(),
        }
    }
    fn digest(&self) -> Digest {
        let elements = vec![
            self.qc_type.to_field(),
            self.view.digest(),
            self.node_digest.to_field(),
        ];
        let bytes: Vec<u8> = elements.hash().enc().collect();
        Digest(bytes.try_into().unwrap_or([0u8; 32]))
    }
    pub fn verify(&self, committee: &Committee) -> ConsensusResult<()> {
        // Ensure the QC has a quorum.
        let mut weight = 0;
        let mut used = HashSet::new();
        for name in self.public_keys.iter() {
            crate::ensure!(!used.contains(name), ConsensusError::AuthorityReuse(*name));
            let voting_rights = committee.stake(name);
            crate::ensure!(voting_rights > 0, ConsensusError::UnknownAuthority(*name));
            used.insert(*name);
            weight += voting_rights;
        }
        if weight < committee.quorum_threshold() {
            error!("QC requires quorum: weight={}, required={}, public_keys={:?}", 
                   weight, committee.quorum_threshold(), self.public_keys);
            return Err(ConsensusError::QCRequiresQuorum);
        }

        // Check the aggregated pk
        let mut public_keys = Vec::with_capacity(self.public_keys.len());
        for pk in self.public_keys.iter() {
            public_keys.push(blst::min_pk::PublicKey::from_bytes(&pk.0).expect("Invalid public key bytes"));
        }
        let pks: Vec<_> = public_keys.iter().collect();
        let aggregated_pk = AggregatePublicKey::aggregate(&pks, true).expect("failed to aggregate public keys");
        if aggregated_pk.to_public_key().to_bytes() != self.agg_pk.0 {
            return Err(ConsensusError::InvalidAggregatedPublicKey);
        }

        // Check the signature.
        verify_signature(&self.digest(), &self.agg_pk, &self.agg_sig)?;
        Ok(())
    }
}

pub struct Consensus;

impl Consensus {
    #[allow(clippy::too_many_arguments)]
    pub fn spawn(
        name: PublicKey,
        committee: Committee,
        parameters: Parameters,
        signature_service: SignatureService,
        store: Store,
        tx_commit: Sender<String>,
    ) { 
        let (msg_tx, msg_rx) = mpsc::unbounded_channel::<(PeerId, ConsensusMessage)>();

        // Create and initialize the P2P network
        let mut p2p = P2pLibp2p::default();
        p2p.init(move |id, payload: Vec<u8>| {
            let msg: ConsensusMessage = bincode::deserialize(&payload)
                .expect("Failed to deserialize message from consensus module");
            if let Err(e) = msg_tx.send((id, msg)) {
                error!("Failed to send message to consensus module: {}", e);
            }
        }).expect("failed to initialize p2p node");
        info!("Local peer ID: {}", p2p.local_peer_id());

        // Wait for leader connection before starting consensus core
        tokio::spawn(async move {
            info!("Waiting for leader connection...");
            
            // Poll the P2P state until we have at least one leader connection
            loop {
                if p2p.has_leader_connection() {
                    info!("Connected to {} leader(s), starting consensus core...", p2p.connected_leader_count());
                    break;
                }
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            }

            // Make the leader election module.
            let leader_elector = LeaderElector::new(committee.clone());

            let replica_client = ReplicaClient::new(env_var_or("REPLICA_ADDRESS", "http://localhost:8080".to_string()));
            // Start the consensus core
            Core::spawn(
                name,
                committee.clone(),
                signature_service.clone(),
                leader_elector,
                store.clone(),
                parameters,
                /* rx_message */ msg_rx,
                p2p,
                tx_commit,
                Arc::new(replica_client),
            );
        });
    }
}

fn env_var_or<T: std::str::FromStr>(key: &str, default: T) -> T {
    std::env::var(key).ok().and_then(|s| s.parse().ok()).unwrap_or(default)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::Digest;

    #[test] 
    fn test_node_digest_with_blob() {
        let parent = Digest([0u8; 32]);
        let test_blob = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000dead00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".to_string();
        
        let node = Node::new(parent, test_blob.clone());
        let digest = node.digest();
        
        println!("Node Digest with Blob: {:?}", digest);
    }
}
