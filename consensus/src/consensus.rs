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
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{collections::HashSet, sync::Arc};
use store::Store;
use tokio::sync::mpsc::{self, Sender};
use zkp::{Scalar, Digest as ZkpDigest, Proof, Vk, mockimpl::MockSignature};
use std::marker::PhantomData;
use crate::utils::digest_to_hex;

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct View<S: Scalar, D: ZkpDigest<S>> {
    pub height: u64,
    pub round: u64,
    #[serde(skip)]
    _phantom: PhantomData<(S, D)>,
}

impl<S: Scalar, D: ZkpDigest<S>> Default for View<S, D> {
    fn default() -> Self {
        Self { height: 1, round: 0, _phantom: PhantomData }
    }
}

impl<S: Scalar, D: ZkpDigest<S>> View<S, D> {
    pub fn digest(&self) -> D {
        let elements = vec![
            S::from_u64(self.height),
            S::from_u64(self.round),
        ];
        D::hash_from_scalars_with_padding(&elements)
    }
}

impl<S: Scalar, D: ZkpDigest<S>> std::fmt::Display for View<S, D> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "View {{ height: {}, round: {} }}", self.height, self.round)
    }
}

impl<S: Scalar, D: ZkpDigest<S>> std::fmt::Debug for View<S, D> {
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
#[serde(bound = "S: Scalar, D: ZkpDigest<S>, P: Proof<S>, V: Vk<N, S, P>")]
pub enum MessagePayload<const N: usize, S: Scalar, D: ZkpDigest<S>, P: Proof<S>, V: Vk<N, S, P>> {
    NewView(QuorumCert<S, D>),
    Prepare(Node<N, S, D, P, V>, QuorumCert<S, D>),
    PrepareVote(Digest<S, D>),
    PreCommit(QuorumCert<S, D>),
    PreCommitVote(Digest<S, D>),
    Commit(QuorumCert<S, D>),
    CommitVote(Digest<S, D>),
    Decide(QuorumCert<S, D>, String),
}

impl<const N: usize, S: Scalar, D: ZkpDigest<S> + DeserializeOwned, P: Proof<S> + DeserializeOwned, V: Vk<N, S, P> + DeserializeOwned> MessagePayload<N, S, D, P, V> {
    pub fn digest(&self) -> Digest<S, D> {
        match self {
            Self::NewView(qc) | Self::PreCommit(qc) | Self::Commit(qc) | Self::Decide(qc, _) => {
                qc.digest()
            }
            Self::Prepare(node, qc) => {
                let elements = vec![node.digest().to_field().to_scalars(), qc.digest().to_field().to_scalars()].concat();
                Digest {
                    value: digest_to_hex(&D::hash_from_scalars_with_padding(&elements)),
                    _phantom: PhantomData,
                }
            }
            Self::PrepareVote(digest) | Self::PreCommitVote(digest) | Self::CommitVote(digest) => {
                digest.clone()
            }
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(bound = "S: Scalar, D: ZkpDigest<S>, P: Proof<S>, V: Vk<N, S, P>")]
pub struct ConsensusMessage<const N: usize, S: Scalar, D: ZkpDigest<S>, P: Proof<S>, V: Vk<N, S, P>> {
    pub msg_type: ConsensusMessageType,
    pub author: PublicKey,
    pub view: View<S, D>,
    pub msg: MessagePayload<N, S, D, P, V>,
    pub signature: Signature,
}

impl<const N: usize, S: Scalar, D: ZkpDigest<S> + DeserializeOwned, P: Proof<S> + DeserializeOwned, V: Vk<N, S, P> + DeserializeOwned> ConsensusMessage<N, S, D, P, V> {
    pub fn digest(&self) -> Digest<S, D> {
        let mut elements = Vec::new();
        elements.push(self.msg_type.to_field());
        elements.extend(self.view.digest().to_scalars());
        elements.extend(self.msg.digest().to_field().to_scalars());
        Digest {
            value: digest_to_hex(&D::hash_from_scalars_with_padding(&elements)),
            _phantom: PhantomData,
        }
    }

    pub async fn new(
        msg_type: ConsensusMessageType,
        author: PublicKey,
        view: View<S, D>,
        msg: MessagePayload<N, S, D, P, V>,
        mut signature_service: SignatureService<S, D>,
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
#[serde(bound = "S: Scalar, D: ZkpDigest<S>, P: Proof<S>, V: Vk<N, S, P>")]
pub struct Node<const N: usize, S: Scalar, D: ZkpDigest<S>, P: Proof<S>, V: Vk<N, S, P>> {
    pub parent: Digest<S, D>,
    pub blob: String,
    #[serde(skip)]
    _phantom: PhantomData<(P, V)>,
}

impl<const N: usize, S: Scalar, D: ZkpDigest<S> + DeserializeOwned, P: Proof<S> + DeserializeOwned, V: Vk<N, S, P> + DeserializeOwned> Node<N, S, D, P, V> {
    pub fn default() -> Self {
        Self {
            parent: Digest::default(), // Genesis node has no parent
            blob: String::new(),
            _phantom: PhantomData,
        }
    }

    pub fn digest(&self) -> Digest<S, D> {
        let blob_digest = if self.blob.is_empty() {
            D::default()
        } else {
            match decode(&self.blob) {
                Ok(bytes) => {
                    match bincode::deserialize::<Blk::<N, S, MockSignature, D, P, V>>(&bytes) {
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
        
        let elements = vec![self.parent.to_field().to_scalars(), blob_digest.to_scalars()].concat();
        Digest {
            value: digest_to_hex(&D::hash_from_scalars_with_padding(&elements)),
            _phantom: PhantomData,
        }
    }

    pub fn new(parent: Digest<S, D>, blob: String) -> Self {
        Self {
            parent,
            blob,
            _phantom: PhantomData,
        }
    }
}

/// QuorumCert represents a quorum certificate with signatures
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(bound = "S: Scalar, D: ZkpDigest<S>")]
pub struct QuorumCert<S: Scalar, D: ZkpDigest<S>> {
    pub qc_type: ConsensusMessageType,
    pub view: View<S, D>,
    pub node_digest: Digest<S, D>,
    pub agg_sig: Signature,
    pub agg_pk: PublicKey,
    pub public_keys: Vec<PublicKey>,
}

impl<S: Scalar, D: ZkpDigest<S>> PartialEq for QuorumCert<S, D> {
    fn eq(&self, other: &Self) -> bool {
        self.qc_type == other.qc_type
            && self.view == other.view
            && self.node_digest == other.node_digest
    }
}

impl<S: Scalar, D: ZkpDigest<S>> QuorumCert<S, D> {
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
    fn digest(&self) -> Digest<S, D> {
        let mut elements = Vec::new();
        elements.push(self.qc_type.to_field());
        elements.extend(self.view.digest().to_scalars());
        elements.extend(self.node_digest.to_field().to_scalars());
        Digest {
            value: digest_to_hex(&D::hash_from_scalars_with_padding(&elements)),
            _phantom: PhantomData,
        }
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
        verify_signature(&self.digest().to_vec(), &self.agg_pk, &self.agg_sig)?;
        Ok(())
    }
}

pub struct Consensus<const N: usize, S: Scalar, D: ZkpDigest<S> + DeserializeOwned, P: Proof<S> + DeserializeOwned, V: Vk<N, S, P> + DeserializeOwned> {
    _phantom: PhantomData<(S, D, P, V)>,
}

impl<S: Scalar, D: ZkpDigest<S> + DeserializeOwned, P: Proof<S> + DeserializeOwned, V: Vk<N, S, P> + DeserializeOwned, const N: usize> Consensus<N, S, D, P, V> {
    #[allow(clippy::too_many_arguments)]
    pub fn spawn(
        name: PublicKey,
        committee: Committee,
        parameters: Parameters,
        signature_service: SignatureService<S, D>,
        store: Store,
        tx_commit: Sender<String>,
    ) { 
        let (msg_tx, msg_rx) = mpsc::unbounded_channel::<(PeerId, ConsensusMessage<N, S, D, P, V>)>();

        // Create and initialize the P2P network
        let mut p2p = P2pLibp2p::default();
        p2p.init(move |id, payload: Vec<u8>| {
            let msg: ConsensusMessage<N, S, D, P, V> = bincode::deserialize(&payload)
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
