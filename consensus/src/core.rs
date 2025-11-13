use crate::aggregator::Aggregator;
use crate::error::ConsensusResult;
use crate::timer::Timer;
use crate::{LeaderElector, Parameters};
use crate::config::Committee;
use crate::consensus::{ConsensusMessage, MessagePayload, QuorumCert, View};
use crypto::{Digest, PublicKey, SignatureService};
use log::{error, warn, info};
use async_recursion::async_recursion;
use network::SimpleSender;
use store::Store;
use tokio::sync::mpsc::{Receiver, Sender};
use crate::utils::verify_signature;

pub struct Core {
    pub name: PublicKey,
    pub committee: Committee,
    pub parameters: Parameters,
    store: Store,
    pub signature_service: SignatureService,
    pub leader_elector: LeaderElector,
    rx_message: Receiver<ConsensusMessage>,
    pub tx_commit: Sender<Digest>,
    pub timer: Timer,
    pub network: SimpleSender,
    pub aggregator: Aggregator,

    // state variables
    pub view: View,
    pub prepare_qc: QuorumCert,
    pub lock_qc: QuorumCert,
    pub lock_blob: Digest,
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
        rx_message: Receiver<ConsensusMessage>,
        tx_commit: Sender<Digest>,
    ) {
        tokio::spawn(async move {     
            let mut core = Self {
                name,
                committee: committee.clone(),
                parameters: parameters.clone(),
                signature_service,
                leader_elector,
                store,
                rx_message,
                tx_commit,
                timer: Timer::new(parameters.timeout_delay),
                network: SimpleSender::new(),
                aggregator: Aggregator::new(committee),

                view: View::default(),
                prepare_qc: QuorumCert::default(),
                lock_qc: QuorumCert::default(),
                lock_blob: Digest::default(),
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
                Some(message) = self.rx_message.recv() => {
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

    fn check_consensus_message(&self, message: &ConsensusMessage) -> ConsensusResult<()> {
        if !self.committee.authorities.contains_key(&message.author) {
            return Err(crate::ConsensusError::NotInCommittee(message.author.encode_base64()));
        }

        verify_signature(&message.digest(), &message.author, &message.signature)?;
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
            (crate::consensus::ConsensusMessageType::Prepare, MessagePayload::PrepareVote(node)) => {
                self.handle_prepare_vote(message.author, message.view, message.signature, node.clone()).await
            },
            (crate::consensus::ConsensusMessageType::PreCommit, MessagePayload::PreCommit(qc)) => {
                self.handle_pre_commit(message.author, message.view, qc.clone()).await
            },
            (crate::consensus::ConsensusMessageType::PreCommit, MessagePayload::PreCommitVote(node)) => {
                self.handle_pre_commit_vote(message.author, message.view, message.signature, node.clone()).await
            },
            (crate::consensus::ConsensusMessageType::Commit, MessagePayload::Commit(qc)) => {
                self.handle_commit(message.author, message.view, qc.clone()).await
            },
            (crate::consensus::ConsensusMessageType::Commit, MessagePayload::CommitVote(node)) => {
                self.handle_commit_vote(message.author, message.view, message.signature, node.clone()).await
            },
            (crate::consensus::ConsensusMessageType::Decide, MessagePayload::Decide(qc)) => {
                self.handle_decide(message.author, message.view, qc.clone()).await
            },
            _ => {
                error!("Mismatched message type and payload");
                Ok(())
            }
        }
    }

    #[async_recursion]
    pub async fn start_new_round(&mut self, round: u64) {
        self.view.round = round;
        self.timer.reset();
        info!("Starting new view {:?}", self.view);
        
        // Send NewView message with current PrepareQC
        if let Err(e) = self.send_new_view().await {
            error!("Failed to send NewView message: {}", e);
        }
    }

    async fn local_timeout_round(&mut self) -> ConsensusResult<()> {
        warn!("Timeout occurred for view {:?}", self.view);
        self.start_new_round(self.view.round + 1).await;
        Ok(())
    }
}