// Core consensus imports
use crate::{
    aggregator::Aggregator,
    config::Committee,
    consensus::{ConsensusMessage, MessagePayload, Node, QuorumCert, View},
    error::ConsensusResult,
    timer::Timer,
    LeaderElector, Parameters,
};

// External crates
use async_recursion::async_recursion;
use crypto::{PublicKey, SignatureService};
use libp2p::PeerId;
use log::{error, info, warn};
use network::P2pLibp2p;
use replica::replica::ReplicaClientApi;
use std::sync::Arc;
use store::Store;
use tokio::sync::mpsc::{self, Sender};
use zkp::{Scalar, Digest as ZkpDigest, Proof, Vk};
use serde::de::DeserializeOwned;

pub struct Core<const N: usize, S: Scalar, D: ZkpDigest<S> + DeserializeOwned + 'static, P: Proof<S> + DeserializeOwned, V: Vk<N, S, P> + DeserializeOwned> {
    // Node identity and configuration
    pub name: PublicKey,
    pub committee: Committee,
    pub parameters: Parameters,
    
    // Core services
    pub signature_service: SignatureService<S, D>,
    pub leader_elector: LeaderElector,
    pub aggregator: Aggregator<S, D>,
    pub replica_client: Arc<dyn ReplicaClientApi>,
    
    // I/O channels
    pub msg_rx: mpsc::UnboundedReceiver<(PeerId, ConsensusMessage<N, S, D, P, V>)>,
    pub tx_commit: Sender<String>,
    pub network: P2pLibp2p,
    
    // Storage and timing
    store: Store,
    pub timer: Timer,
    
    // Consensus state
    pub view: View<S, D>,
    pub voted_node: Node<N, S, D, P, V>,
    pub prepare_qc: QuorumCert<S, D>,
    pub lock_qc: QuorumCert<S, D>,
    pub lock_blob: String,
    pub consecutive_timeouts: u64,
}

impl<const N: usize, S: Scalar, D: ZkpDigest<S> + DeserializeOwned + 'static, P: Proof<S> + DeserializeOwned, V: Vk<N, S, P> + DeserializeOwned> Core<N, S, D, P, V> {
    #[allow(clippy::too_many_arguments)]
    pub fn spawn(
        name: PublicKey,
        committee: Committee,
        signature_service: SignatureService<S, D>,
        leader_elector: LeaderElector,
        store: Store,
        parameters: Parameters,
        msg_rx: mpsc::UnboundedReceiver<(PeerId, ConsensusMessage<N, S, D, P, V>)>,
        network: P2pLibp2p,
        tx_commit: Sender<String>,
        replica_client: Arc<dyn ReplicaClientApi>,
    ) {
        tokio::spawn(async move {     
            let mut core = Self {
                name,
                committee: committee.clone(),
                parameters: parameters.clone(),
                signature_service,
                leader_elector,
                store,
                msg_rx,
                tx_commit,
                timer: Timer::new(parameters.timeout_delay),
                network,
                aggregator: Aggregator::new(committee),
                replica_client,

                view: View::default(),
                voted_node: Node::default(),
                prepare_qc: QuorumCert::default(),
                lock_qc: QuorumCert::default(),
                lock_blob: String::new(),
                consecutive_timeouts: 0,
            };
            
            // Restore persistent state from storage
            core.restore_persistent_state().await;
            
            core.run().await;
        });
    }

    pub async fn run(&mut self) {
        info!("HotStuff consensus core started for node {}", self.name);
        
        // Start the timer for the first round
        self.start_new_round(0).await;

        // Main consensus loop
        loop {
            let result = tokio::select! {
                Some((_peer_id, message)) = self.msg_rx.recv() => {
                    // Check message
                    match self.check_consensus_message(&message) {
                        Ok(_) => self.handle_consensus_message(message).await,
                        Err(e) => Err(e.into()),
                    }
                },
                () = &mut self.timer => self.local_timeout_round().await,
            };
            
            if let Err(e) = result {
                error!("Consensus error: {}", e);
            }
        }
    }

    fn check_consensus_message(&self, _: &ConsensusMessage<N, S, D, P, V>) -> ConsensusResult<()> {
        //TODO: already checked in network layer
        // if !self.committee.authorities.contains_key(&message.author) {
        //     error!("Received {:?} message from unknown author: {:?}", message.msg_type.to_string(), message.author);
        //     return Err(crate::ConsensusError::NotInCommittee(message.author.encode_base64()));
        // }

        // verify_signature(&message.digest(), &message.author, &message.signature)?;
        Ok(())
    }

    async fn handle_consensus_message(&mut self, message: ConsensusMessage<N, S, D, P, V>) -> ConsensusResult<()> {
        use crate::consensus::ConsensusMessageType as MsgType;
        
        match (message.msg_type, message.msg) {
            (MsgType::NewView, MessagePayload::NewView(qc)) => {
                self.handle_new_view(message.author, message.view, qc).await
            }
            (MsgType::Prepare, MessagePayload::Prepare(node, qc)) => {
                self.handle_prepare(message.author, message.view, node, qc).await
            }
            (MsgType::PreCommit, MessagePayload::PreCommit(qc)) => {
                self.handle_pre_commit(message.author, message.view, qc).await
            }
            (MsgType::Commit, MessagePayload::Commit(qc)) => {
                self.handle_commit(message.author, message.view, qc).await
            }
            (MsgType::Decide, MessagePayload::Decide(qc, wp_blk)) => {
                self.handle_decide(message.author, message.view, qc, wp_blk).await
            }
            _ => {
                error!(
                    "Mismatched message type {:?} and payload for message from {}",
                    message.msg_type, message.author
                );
                Err(crate::ConsensusError::InvalidPayload)
            }
        }
    }

    #[async_recursion]
    pub async fn start_new_round(&mut self, round: u64) {
        // Get proposal from replica to determine height
        let height = match self.fetch_and_parse_proposal().await {
            Some((_, height)) => height,
            None => {
                warn!("Failed to get proposal for round {}, using previous height", round);
                return;
            }
        };

        // Update view state
        self.view.height = height;
        self.view.round = round;
        self.voted_node = Node::default();
        self.persist_voted_node().await;
        self.timer.reset();
        
        info!("Starting new view: {}", self.view);
        
        // Send NewView message with current PrepareQC
        if let Err(e) = self.send_new_view().await {
            error!("Failed to send NewView message for view {}: {}", self.view, e);
        }
    }

    async fn local_timeout_round(&mut self) -> ConsensusResult<()> {
        self.consecutive_timeouts += 1;
        warn!(
            "Timeout occurred for view {} (consecutive: {})",
            self.view, self.consecutive_timeouts
        );
        
        // Calculate new timeout with exponential backoff
        let new_timeout = self.calculate_timeout_duration();
        self.timer = Timer::new(new_timeout);
        
        // Move to next round
        self.start_new_round(self.view.round + 1).await;
        Ok(())
    }
    
    fn calculate_timeout_duration(&self) -> u64 {
        if self.consecutive_timeouts == 0 {
            return self.parameters.timeout_delay;
        }
        
        // Use saturating arithmetic to prevent overflow
        let backoff_multiplier = 2_u64.saturating_pow((self.consecutive_timeouts - 1) as u32);
        
        self.parameters.timeout_delay.saturating_mul(backoff_multiplier)
    }
    
    // Persistence methods
    async fn restore_persistent_state(&mut self) {
        // Restore voted_node
        if let Ok(Some(voted_node_bytes)) = self.store.read_voted_node().await {
            if let Ok(voted_node) = postcard::from_bytes::<Node<N, S, D, P, V>>(&voted_node_bytes) {
                self.voted_node = voted_node;
                info!("Restored voted_node: {}", self.voted_node.digest());
            }
        }
        
        // Restore prepare_qc
        if let Ok(Some(prepare_qc_bytes)) = self.store.read_prepare_qc().await {
            if let Ok(prepare_qc) = postcard::from_bytes::<QuorumCert<S, D>>(&prepare_qc_bytes) {
                self.prepare_qc = prepare_qc;
                info!("Restored prepare_qc for view: {}", self.prepare_qc.view);
            }
        }
        
        // Restore lock_qc
        if let Ok(Some(lock_qc_bytes)) = self.store.read_lock_qc().await {
            if let Ok(lock_qc) = postcard::from_bytes::<QuorumCert<S, D>>(&lock_qc_bytes) {
                self.lock_qc = lock_qc;
                info!("Restored lock_qc for view: {}", self.lock_qc.view);
            }
        }
        
        // Restore lock_blob
        if let Ok(Some(lock_blob)) = self.store.read_lock_blob().await {
            self.lock_blob = lock_blob;
            info!("Restored lock_blob: {} chars", self.lock_blob.len());
        }
    }
    
    pub async fn persist_voted_node(&mut self) {
        if let Ok(bytes) = postcard::to_allocvec(&self.voted_node) {
            self.store.write_voted_node(bytes).await;
        }
    }
    
    pub async fn persist_prepare_qc(&mut self) {
        if let Ok(bytes) = postcard::to_allocvec(&self.prepare_qc) {
            self.store.write_prepare_qc(bytes).await;
        }
    }
    
    pub async fn persist_lock_qc(&mut self) {
        if let Ok(bytes) = postcard::to_allocvec(&self.lock_qc) {
            self.store.write_lock_qc(bytes).await;
        }
    }
    
    pub async fn persist_lock_blob(&mut self) {
        self.store.write_lock_blob(self.lock_blob.clone()).await;
    }
}