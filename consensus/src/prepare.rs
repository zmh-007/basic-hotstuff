use crate::{
    consensus::{ConsensusMessage, ConsensusMessageType, MessagePayload, Node, QuorumCert, View},
    core::Core,
    error::{ConsensusError, ConsensusResult},
};
use crypto::{Digest, PublicKey};
use log::{debug, error, info, warn};

impl Core {
    pub async fn send_prepare(&mut self, high_qc: QuorumCert) -> ConsensusResult<()> {
        info!("Sending Prepare message for view {}", self.view);
        
        if !self.check_is_leader(&self.view) {
            warn!("Cannot send Prepare message - not the leader for view {}", self.view);
            return Ok(());
        }
        
        // Get blob - use locked blob or fetch new proposal
        let blob = if !self.lock_blob.is_empty() {
            info!("Using locked blob for Prepare message");
            self.lock_blob.clone()
        } else {
            match self.fetch_and_parse_proposal().await {
                Some((blk, _)) => blk,
                None => {
                    error!("Failed to get proposal for Prepare message");
                    return Ok(());
                }
            }
        };

        let node = Node::new(high_qc.node_digest, blob);
        let prepare_message = ConsensusMessage::new(
            ConsensusMessageType::Prepare,
            self.name,
            self.view.clone(),
            MessagePayload::Prepare(node.clone(), high_qc.clone()),
            self.signature_service.clone(),
        ).await;

        let payload = bincode::serialize(&prepare_message)
            .map_err(ConsensusError::SerializationError)?;
            
        debug!("Broadcasting Prepare message for view {}", self.view);
        self.network.send(None, payload)?;
        self.handle_prepare(self.name, self.view.clone(), node, high_qc).await
    }

    pub async fn handle_prepare(
        &mut self,
        _author: PublicKey,
        view: View,
        node: Node,
        high_qc: QuorumCert,
    ) -> ConsensusResult<()> {
        info!("Received Prepare for view {}", view);
        if view != self.view {
            debug!("Ignoring Prepare for view {} (current: {})", view, self.view);
            return Ok(());
        }
        
        if high_qc.qc_type != ConsensusMessageType::Prepare {
            error!("Invalid QC type in Prepare: {:?}", high_qc.qc_type);
            return Ok(());
        }
        
        if self.voted_node != Node::default() {
            warn!(
                "Already voted for view {} (node: {}), ignoring new Prepare (node: {})",
                view, self.voted_node.digest(), node.digest()
            );
            return Ok(());
        }

        if high_qc != QuorumCert::default() {
            high_qc.verify(&self.committee)?;
        }

        // Check if we should use locked blob (only for same height)
        if !self.lock_blob.is_empty() && self.lock_qc.view.height == view.height {
            // If we have a locked blob for the same height, the proposal must match it
            if node.blob != self.lock_blob {
                error!(
                    "Proposal mismatch for height {}: expected locked blob '{}', got '{}'", 
                    view.height, self.lock_blob, node.blob
                );
                return Ok(());
            }
            info!("Using locked blob for proposal verification at height {}", view.height);
        } else {
            if let Err(error) = self.replica_client.verify_proposal(node.blob.clone()).await {
                error!("Proposal verification failed: {:?}", error);
                return Ok(());
            }
            info!("Proposal verification successful");
        }

        // Apply safety and liveness rules
        self.extend(&node, &high_qc)?;
        self.safe_node(&node, &high_qc)?;
        
        self.voted_node = node.clone();
        self.persist_voted_node().await;
        self.send_prepare_vote(node.digest()).await
    }

    fn extend(&self, node: &Node, high_qc: &QuorumCert) -> ConsensusResult<()> {        
        if node.parent != high_qc.node_digest {
            return Err(ConsensusError::InvalidQC(
                format!("expect parent {:?}, got {:?}", high_qc.node_digest, node.parent)
            ));
        }
        Ok(())
    }

    fn safe_node(&self, node: &Node, high_qc: &QuorumCert) -> ConsensusResult<()> {
        if self.lock_qc == QuorumCert::default() {
            debug!("No lock QC (genesis), node is safe");
            return Ok(());
        }

        let high_view = (high_qc.view.height, high_qc.view.round);
        let lock_view = (self.lock_qc.view.height, self.lock_qc.view.round);
        
        // Safety conditions (either must be true):
        // 1. highQC.view > lockQC.view OR
        // 2. node extends lockQC (node's parent equals lockQC's node)
        let higher_view = high_view > lock_view;
        let extends_lock = node.parent == self.lock_qc.node_digest;
        
        if higher_view {
            debug!("Node is safe: higher view ({:?} > {:?})", high_view, lock_view);
            Ok(())
        } else if extends_lock {
            debug!("Node is safe: extends locked node");
            Ok(())
        } else {
            Err(ConsensusError::SafeNodeViolation(format!(
                "Node safety violation: highQC view {:?} <= lockQC view {:?} and node doesn't extend lockQC",
                high_qc.view, self.lock_qc.view
            )))
        }
    }

    pub async fn send_prepare_vote(&mut self, node_digest: Digest) -> ConsensusResult<()> {
        info!("Sending PrepareVote message");
        let prepare_vote_message = ConsensusMessage::new(
            ConsensusMessageType::Prepare,
            self.name,
            self.view.clone(), 
            MessagePayload::PrepareVote(node_digest),
            self.signature_service.clone(),
        ).await;

        match bincode::serialize(&prepare_vote_message) {
            Ok(payload) => {
                let leader = self.leader_elector.get_leader(&self.view);
                debug!("Sending PrepareVote {:?} to leader {:?}", node_digest, leader);
                self.network.send(None, payload)?;
                debug!("PrepareVote message sent successfully");
            }
            Err(e) => {
                return Err(ConsensusError::SerializationError(e));
            }
        }
        Ok(())
    }

    pub async fn fetch_and_parse_proposal(&self) -> Option<(String, u64)> {
        match self.replica_client.get_proposal().await {
            Ok(value) => {
                let proposal_obj = match value.as_object() {
                    Some(s) => s,
                    None => {
                        error!("proposal value is not a valid struct");
                        return None;
                    }
                };
                let sequence = proposal_obj.get("index").and_then(|v| v.as_str()).unwrap_or("0");
                let sequence = sequence.parse::<u64>().unwrap_or(0);
                let mut blk = match proposal_obj.get("block").and_then(|v| v.as_str()) {
                    Some(b) => b.to_string(),
                    None => {
                        error!("invalid block in proposal");
                        return None;
                    }
                };
                if blk.starts_with("0x") {
                    blk = blk.trim_start_matches("0x").to_string();
                }
                info!("Success get proposal: sequence={}, blk={}", sequence, blk);
                Some((blk, sequence))
            }
            Err(error) => {
                error!("failed to get proposal: {:?}", error);
                None
            }
        }
    }
}
