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
use zkp::{Scalar, Digest as ZkpDigest, Proof, Vk};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
pub struct View {
    pub height: u64,
    pub round: u64,
}

impl View {
    pub fn default() -> Self {
        Self { height: 1, round: 0 }
    }

    pub fn digest<S: Scalar, D: ZkpDigest<S>>(&self) -> D {
        let elements = vec![
            S::from_u64(self.height),
            S::from_u64(self.round),
        ];
        D::hash_from_scalars_with_padding(&elements)
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
    fn to_field<S: Scalar>(&self) -> S {
        match self {
            ConsensusMessageType::Prepare => S::from_u64(0u64),
            ConsensusMessageType::PreCommit => S::from_u64(1u64),
            ConsensusMessageType::Commit => S::from_u64(2u64),
            ConsensusMessageType::Decide => S::from_u64(3u64),
            ConsensusMessageType::NewView => S::from_u64(4u64),
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
    pub fn digest<const N: usize, S: Scalar, D: ZkpDigest<S>, P: Proof<S>, V: Vk<N, S, P>>(&self) -> Digest {
        match self {
            Self::NewView(qc) | Self::PreCommit(qc) | Self::Commit(qc) | Self::Decide(qc, _) => {
                qc.digest::<S, D>()
            }
            Self::Prepare(node, qc) => {
                let elements = vec![node.digest::<N, S, D, P, V>().to_field::<S, D>().to_scalars(), qc.digest::<S, D>().to_field::<S, D>().to_scalars()].concat();
                Digest(D::hash_from_scalars_with_padding(&elements).to_hex())
            }
            Self::PrepareVote(digest) | Self::PreCommitVote(digest) | Self::CommitVote(digest) => {
                digest.clone()
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
    pub fn digest<const N: usize, S: Scalar, D: ZkpDigest<S>, P: Proof<S>, V: Vk<N, S, P>>(&self) -> Digest {
        let mut elements = Vec::new();
        elements.push(self.msg_type.to_field());
        elements.extend(self.view.digest::<S, D>().to_scalars());
        elements.extend(self.msg.digest::<N, S, D, P, V>().to_field::<S, D>().to_scalars());
        Digest(D::hash_from_scalars_with_padding(&elements).to_hex())
    }

    pub async fn new<const N: usize, S: Scalar, D: ZkpDigest<S>, P: Proof<S>, V: Vk<N, S, P>>(
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
        
        let signature = signature_service.request_signature(message.digest::<N, S, D, P, V>()).await;
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

    pub fn digest<const N: usize, S: Scalar, D: ZkpDigest<S>, P: Proof<S>, V: Vk<N, S, P>>(&self) -> Digest {
        let blob_digest = if self.blob.is_empty() {
            D::default()
        } else {
            match decode(&self.blob) {
                Ok(bytes) => {
                    match Blk::<N, S, D, P, V>::dec(&mut bytes.into_iter()) {
                        Ok(blk) => blk.hash(),
                        Err(_) => {
                            error!("Failed to decode block from blob: {}", self.blob);
                            D::default()
                        }
                    }
                }
                Err(_) => {
                    error!("Failed to decode hex blob: {}", self.blob);
                    D::default()
                }
            }
        };
        
        let elements = vec![self.parent.to_field::<S, D>().to_scalars(), blob_digest.to_scalars()].concat();
        Digest(D::hash_from_scalars_with_padding(&elements).to_hex())
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
    fn digest<S: Scalar, D: ZkpDigest<S>>(&self) -> Digest {
        let mut elements = Vec::new();
        elements.push(self.qc_type.to_field());
        elements.extend(self.view.digest::<S, D>().to_scalars());
        elements.extend(self.node_digest.to_field::<S, D>().to_scalars());
        Digest(D::hash_from_scalars_with_padding(&elements).to_hex())
    }
    pub fn verify<S: Scalar, D: ZkpDigest<S>>(&self, committee: &Committee) -> ConsensusResult<()> {
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
        verify_signature(&self.digest::<S, D>(), &self.agg_pk, &self.agg_sig)?;
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
