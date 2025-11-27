use crate::consensus::{ConsensusMessage, ConsensusMessageType, MessagePayload, Node, QuorumCert, View};
use crate::core::Core;
use crate::error::ConsensusResult;
use crypto::{Digest, PublicKey};
use log::{debug, info, error};
use crate::ConsensusError;

impl Core {
    /// Send Prepare message with current PrepareQC
    pub async fn send_prepare(&mut self, high_qc: QuorumCert) -> ConsensusResult<()> {
        info!("Sending Prepare message");
        if !self.check_is_leader(&self.view) {
            error!("Not the leader for view {:?}, cannot send Prepare message", self.view);
            return Ok(());
        }
        
        // check if blob is locked, else get proposal from replica
        let blob = if self.lock_blob != String::new() {
            self.lock_blob.clone()
        } else {
            // get proposal from replica
            match self.fetch_and_parse_proposal().await {
                Some((blk, _)) => blk,
                None => return Ok(()),
            }
        };

        let parent = high_qc.node_digest.clone();
        let node = Node::new(parent, blob);

        // Create the prepare message with signature service
        let prepare_message = ConsensusMessage::new(
            ConsensusMessageType::Prepare,
            self.name,
            self.view.clone(), 
            MessagePayload::Prepare(node.clone(), high_qc.clone()),
            self.signature_service.clone(),
        ).await;

       // Serialize the message
        match bincode::serialize(&prepare_message) {
            Ok(payload) => {
                // broadcast the message
                debug!("Broadcast {:?}", prepare_message);
                self.network.send(None, payload)?;
                debug!("Prepare message broadcast successfully");
                self.handle_prepare(self.name, self.view.clone(), node, high_qc).await?;
            }
            Err(e) => {
                return Err(ConsensusError::SerializationError(e));
            }
        }
        Ok(())
    }

    pub async fn handle_prepare(&mut self, _: PublicKey, view: View, node: Node, high_qc: QuorumCert) -> ConsensusResult<()> {
        info!("Received prepare for view {:?}", view);
        if view != self.view {
            return Ok(());
        }
        if high_qc.qc_type != ConsensusMessageType::Prepare {
            error!("Received prepare with invalid QC type: {:?}", high_qc.qc_type);
            return Ok(());
        }
        if high_qc != QuorumCert::default() {
            high_qc.verify(&self.committee)?;
        }
        if self.voted_node != Node::default() {
            error!("Received prepare for view {:?}, but node digest {:?} is voted already to digest {:?}", 
                  view, node.digest(), self.voted_node.digest());
            return Ok(());
        }

        // verify proposal from replica
        match self.replica_client.verify_proposal(node.blob.clone()).await {
            Ok(_) => {
                info!("Success verify proposal");
            }
            Err(error) => {
                error!("failed to verify proposal: {:?}", error);
                return Ok(());
            }
        }

        // safety and liveness rules
        self.extend(&node, &high_qc)?;
        self.safe_node(&node, &high_qc)?;
        self.voted_node = node.clone();

        self.send_prepare_vote(node.digest()).await?;
        Ok(())
    }

    fn extend(&self, node: &Node, high_qc: &QuorumCert) -> ConsensusResult<()> {        
        // Check if the node's parent matches the QC's node
        if node.parent != high_qc.node_digest {
            return Err(ConsensusError::InvalidQC(
                format!("expect parent {:?}, got {:?}", high_qc.node_digest, node.parent)
            ));
        }
        Ok(())
    }

    fn safe_node(&self, node: &Node, high_qc: &QuorumCert) -> ConsensusResult<()> {
        let lock_qc = self.lock_qc.clone();
        
        // Skip genesis block
        if lock_qc == QuorumCert::default() {
            info!("LockQC is default - should only happen at startup");
            return Ok(());
        }

        // Check safety conditions:
        // 1. highQC.view > lockQC.view OR
        // 2. node extends lockQC (node's parent equals lockQC's node)
        if (high_qc.view.height, high_qc.view.round) > (lock_qc.view.height, lock_qc.view.round) {
            return Ok(());
        }
        if node.parent == lock_qc.node_digest {
            return Ok(());
        }

        Err(ConsensusError::SafeNodeViolation(
            format!("Node is not safe: highQC.view {} <= lockQC.view {} and node doesn't extend lockQC", 
                   high_qc.view, lock_qc.view)
        ))
    }

    pub async fn send_prepare_vote(&mut self, node_digest: Digest) -> ConsensusResult<()> {
        info!("Sending PrepareVote message");
        
        // Create the prepare vote message with signature service
        let prepare_vote_message = ConsensusMessage::new(
            ConsensusMessageType::Prepare,
            self.name,
            self.view.clone(), 
            MessagePayload::PrepareVote(node_digest),
            self.signature_service.clone(),
        ).await;

       // Serialize the message
        match bincode::serialize(&prepare_vote_message) {
            Ok(payload) => {
                // send the message to leader
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
