use crate::{LeaderElector, config::{Committee, Parameters}, core::Core, error::ConsensusResult};
use crate::ConsensusError;
use async_trait::async_trait;
use bytes::Bytes;
use crypto::{Digest, PublicKey, SignatureService, Signature};
use hex::decode;
use l0::Blk;
use log::{info};
use network::{MessageHandler, Receiver as NetworkReceiver, Writer};
use serde::{Deserialize, Serialize};
use zk::{AsBytes, ToHash, Fr};
use std::{collections::HashSet, error::Error};
use store::Store;
use tokio::sync::mpsc::{channel, Sender};
use crate::utils::verify_signature;

/// The default channel capacity for each channel of the consensus.
pub const CHANNEL_CAPACITY: usize = 1_000;

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
    Decide(QuorumCert),
}

impl MessagePayload {
    pub fn digest(&self) -> Digest {
        match self {
            MessagePayload::NewView(qc)
            | MessagePayload::PreCommit(qc)
            | MessagePayload::Commit(qc)
            | MessagePayload::Decide(qc) => qc.digest(),
            MessagePayload::Prepare(node, qc) => {
                // Combine node and qc digests
                let elements = vec![
                    node.digest().to_field(),
                    qc.digest().to_field(),
                ];
                let b: Vec<u8> = elements.hash().enc().collect();
                Digest(b.try_into().expect("Failed to convert prepare payload hash bytes to digest"))
            },
            MessagePayload::PrepareVote(node_digest)
            | MessagePayload::PreCommitVote(node_digest)
            | MessagePayload::CommitVote(node_digest) => *node_digest,
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
        let b: Vec<u8> = elements.hash().enc().collect();
        Digest(b.try_into().expect("Failed to convert message hash bytes to digest"))
    }

    pub async fn new(
        msg_type: ConsensusMessageType,
        author: PublicKey,
        view: View,
        msg: MessagePayload, 
        mut signature_service: SignatureService,
    ) -> Self {
        let m = Self {
            msg_type,
            author,
            view,
            msg,
            signature: Signature::default(),
        };
        let sig = signature_service.request_signature(m.digest()).await;
        Self { signature: sig, ..m }
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
            let b = decode(self.blob.clone()).unwrap();
            let blk = Blk::dec(&mut b.into_iter()).unwrap();
            blk.hash()
        };
        let elements = vec![
            self.parent.to_field(),
            blob_digest,
        ];
        let b: Vec<u8> = elements.hash().enc().collect();
        Digest(b.try_into().expect("Failed to convert node hash bytes to digest"))
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
    pub signatures: Vec<(PublicKey, Signature)>,
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
            signatures: Vec::new(),
        }
    }
    pub fn new(qc_type: ConsensusMessageType, view: View, node_digest: Digest) -> Self {
        Self {
            qc_type,
            view,
            node_digest,
            signatures: Vec::new(),
        }
    }
    fn digest(&self) -> Digest {
        let elements = vec![
            self.qc_type.to_field(),
            self.view.digest(),
            self.node_digest.to_field(),
        ];
        let b: Vec<u8> = elements.hash().enc().collect();
        Digest(b.try_into().expect("Failed to convert qc hash bytes to digest"))
    }
    pub fn verify(&self, committee: &Committee) -> ConsensusResult<()> {
        // Ensure the QC has a quorum.
        let mut weight = 0;
        let mut used = HashSet::new();
        for (name, _) in self.signatures.iter() {
            crate::ensure!(!used.contains(name), ConsensusError::AuthorityReuse(*name));
            let voting_rights = committee.stake(name);
            crate::ensure!(voting_rights > 0, ConsensusError::UnknownAuthority(*name));
            used.insert(*name);
            weight += voting_rights;
        }
        crate::ensure!(
            weight >= committee.quorum_threshold(),
            ConsensusError::QCRequiresQuorum
        );

        // Check the signature.
        for (author, sig) in &self.signatures {
            verify_signature(&self.digest(), author, sig)?;
        }
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
        tx_commit: Sender<Digest>,
    ) { 
        let (tx_consensus, rx_consensus) = channel(CHANNEL_CAPACITY);

        // Spawn the network receiver.
        let mut address = committee
            .address(&name)
            .expect("Our public key is not in the committee");
        address.set_ip("0.0.0.0".parse().unwrap());
        NetworkReceiver::spawn(
            address,
            /* handler */
            ConsensusReceiverHandler {
                tx_consensus,
            },
        );
        info!(
            "Node {} listening to consensus messages on {}",
            name, address
        );

        // Make the leader election module.
        let leader_elector = LeaderElector::new(committee.clone());

        // Spawn the consensus core.
        Core::spawn(
            name,
            committee.clone(),
            signature_service.clone(),
            leader_elector,
            store.clone(),
            parameters,
            /* rx_message */ rx_consensus,
            tx_commit,
        );
    }
}

/// Defines how the network receiver handles incoming primary messages.
#[derive(Clone)]
struct ConsensusReceiverHandler {
    tx_consensus: Sender<ConsensusMessage>,
}

#[async_trait]
impl MessageHandler for ConsensusReceiverHandler {
    async fn dispatch(&self, _writer: &mut Writer, serialized: Bytes) -> Result<(), Box<dyn Error>> {
        // Deserialize and parse the message.
        let message: ConsensusMessage = bincode::deserialize(&serialized)
            .map_err(ConsensusError::from)?;
        
        self.tx_consensus
            .send(message)
            .await
            .map_err(|e| Box::new(e) as Box<dyn Error>)?;
        
        Ok(())
    }
}