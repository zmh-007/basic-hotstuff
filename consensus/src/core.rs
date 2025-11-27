use crate::aggregator::Aggregator;
use crate::error::ConsensusResult;
use crate::timer::Timer;
use crate::{LeaderElector, Parameters};
use crate::config::Committee;
use crate::consensus::{ConsensusMessage, MessagePayload, Node, QuorumCert, View};
use crypto::{PublicKey, SignatureService};
use libp2p::PeerId;
use log::{error, warn, info};
use async_recursion::async_recursion;
use network::P2pLibp2p;
use replica::replica::ReplicaClientApi;
use store::Store;
use tokio::sync::mpsc::{self, Sender};
use std::sync::Arc;

pub struct Core {
    pub name: PublicKey,
    pub committee: Committee,
    pub parameters: Parameters,
    store: Store,
    pub signature_service: SignatureService,
    pub leader_elector: LeaderElector,
    pub msg_rx: mpsc::UnboundedReceiver<(PeerId, ConsensusMessage)>,
    pub tx_commit: Sender<String>,
    pub timer: Timer,
    pub network: P2pLibp2p,
    pub aggregator: Aggregator,
    pub replica_client: Arc<dyn ReplicaClientApi>,

    // state variables
    pub view: View,
    pub voted_node: Node,
    pub prepare_qc: QuorumCert,
    pub lock_qc: QuorumCert,
    pub lock_blob: String,
    
    // View synchronization
    pub consecutive_timeouts: u64,
}

impl Core {
    #[allow(clippy::too_many_arguments)]
    pub fn spawn(
        name: PublicKey,
        committee: Committee,
        signature_service: SignatureService,
        leader_elector: LeaderElector,
        store: Store,
        parameters: Parameters,
        msg_rx: mpsc::UnboundedReceiver<(PeerId, ConsensusMessage)>,
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

    fn check_consensus_message(&self, _: &ConsensusMessage) -> ConsensusResult<()> {
        //TODO: already checked in network layer
        // if !self.committee.authorities.contains_key(&message.author) {
        //     error!("Received {:?} message from unknown author: {:?}", message.msg_type.to_string(), message.author);
        //     return Err(crate::ConsensusError::NotInCommittee(message.author.encode_base64()));
        // }

        // verify_signature(&message.digest(), &message.author, &message.signature)?;
        Ok(())
    }

    async fn handle_consensus_message(&mut self, message: ConsensusMessage) -> ConsensusResult<()> {
        match (&message.msg_type, &message.msg) {
            (crate::consensus::ConsensusMessageType::NewView, MessagePayload::NewView(qc)) => {
                self.handle_new_view(message.author, message.view, qc.clone()).await
            },
            (crate::consensus::ConsensusMessageType::Prepare, MessagePayload::Prepare(node, qc)) => {
                self.handle_prepare(message.author, message.view, node.clone(), qc.clone()).await
            },
            (crate::consensus::ConsensusMessageType::PreCommit, MessagePayload::PreCommit(qc)) => {
                self.handle_pre_commit(message.author, message.view, qc.clone()).await
            },
            (crate::consensus::ConsensusMessageType::Commit, MessagePayload::Commit(qc)) => {
                self.handle_commit(message.author, message.view, qc.clone()).await
            },
            (crate::consensus::ConsensusMessageType::Decide, MessagePayload::Decide(qc, wp_blk)) => {
                self.handle_decide(message.author, message.view, qc.clone(), wp_blk.to_string()).await
            },
            _ => {
                error!("Mismatched message type {:?} and payload", message.msg_type);
                Err(crate::ConsensusError::InvalidPayload)
            }
        }
    }

    #[async_recursion]
    pub async fn start_new_round(&mut self, round: u64) {
        // get proposal from replica to get height
        let height = match self.fetch_and_parse_proposal().await {
            Some((_, height)) => height,
            None => return,
        };

        self.view.round = round;
        self.view.height = height;
        self.voted_node = Node::default();
        self.timer.reset();
        info!("Starting new view {:?}", self.view);
        
        // Send NewView message with current PrepareQC
        if let Err(e) = self.send_new_view().await {
            error!("Failed to send NewView message: {}", e);
        }
    }

    async fn local_timeout_round(&mut self) -> ConsensusResult<()> {
        self.consecutive_timeouts += 1;
        warn!("Timeout occurred for view {:?} (consecutive: {})", 
              self.view, self.consecutive_timeouts);
        // Apply exponential backoff for timeout duration with overflow protection
        let new_timeout = if self.consecutive_timeouts == 0 {
            self.parameters.timeout_delay
        } else {
            // Use saturating arithmetic to prevent overflow
            let backoff_multiplier = 2_u64.saturating_pow((self.consecutive_timeouts - 1) as u32);
            self.parameters.timeout_delay.saturating_mul(backoff_multiplier)
        };
               
        // Update timer with new timeout
        self.timer = Timer::new(new_timeout);
        self.start_new_round(self.view.round + 1).await;
        Ok(())
    }
}