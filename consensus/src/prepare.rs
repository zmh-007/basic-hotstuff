use crate::{
    consensus::{ConsensusMessage, ConsensusMessageType, MessagePayload, Node, QuorumCert, View},
    core::Core,
    error::{ConsensusError, ConsensusResult},
};
use crypto::{Digest, PublicKey};
use log::{debug, error, info, warn};
use tokio::time;
use zkp::{Scalar, Digest as ZkpDigest, Proof, Vk, SafeU256};
use serde::de::DeserializeOwned;

/// Timeout for replica RPC calls (in seconds)
const REPLICA_TIMEOUT_SECS: u64 = 10;

impl<const N: usize, S: Scalar, D: ZkpDigest<S> + DeserializeOwned + 'static, U: SafeU256<Scalar=S> + DeserializeOwned + 'static, P: Proof<S> + DeserializeOwned, V: Vk<N, S, P> + DeserializeOwned> Core<N, S, D, U, P, V> {
    pub async fn send_prepare(&mut self, high_qc: QuorumCert<S, D>) -> ConsensusResult<()> {
        info!("Sending Prepare message for view {}", self.view);
        
        if !self.check_is_leader(self.view) {
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

        let node = Node::<N, S, D, U, P, V>::new(high_qc.node_digest.clone(), blob);
        let prepare_message = ConsensusMessage::<N, S, D, U, P, V>::new(
            ConsensusMessageType::Prepare,
            self.name,
            self.view.clone(),
            MessagePayload::<N, S, D, U, P, V>::Prepare(node.clone(), high_qc.clone()),
            self.signature_service.clone(),
        ).await;

        let payload = postcard::to_allocvec(&prepare_message)
            .map_err(|e| ConsensusError::SerializationError(e.to_string()))?;
            
        debug!("Broadcasting Prepare message for view {}", self.view);
        self.network.send(None, payload)?;
        self.handle_prepare(self.name, self.view.clone(), node, high_qc).await
    }

    pub async fn handle_prepare(
        &mut self,
        author: PublicKey,
        view: View,
        node: Node<N, S, D, U, P, V>,
        high_qc: QuorumCert<S, D>,
    ) -> ConsensusResult<()> {
        info!("Received Prepare for view {}", view);
        if view != self.view {
            debug!("Ignoring Prepare for view {} (current: {})", view, self.view);
            return Ok(());
        }
        
        // Verify the sender is the leader for this view
        let expected_leader = self.leader_elector.get_leader(view);
        if author != expected_leader {
            error!("Received Prepare from non-leader: {:?}, expected: {:?}", author, expected_leader);
            return Ok(());
        }
        
        if high_qc.qc_type != ConsensusMessageType::Prepare {
            error!("Invalid QC type in Prepare: {:?}", high_qc.qc_type);
            return Ok(());
        }
        
        // Check if we already voted in this view
        if self.voted_node != Node::<N, S, D, U, P, V>::default() && self.voted_view == view {
            warn!(
                "Already voted for view {} (node: {}), ignoring new Prepare (node: {})",
                view, self.voted_node.digest(), node.digest()
            );
            return Ok(());
        }

        if high_qc != QuorumCert::<S, D>::default() {
            high_qc.verify(&self.committee)?;
        }

        // If we have a locked blob, check if the proposal matches or has a higher QC
        if !self.lock_blob.is_empty() {
            if node.blob != self.lock_blob {
                // Allow proposals with a higher QC to override the lock (liveness rule)
                if high_qc.view <= self.lock_qc.view {
                    error!(
                        "Proposal mismatch: expected locked blob, and highQC view {} <= lockQC view {}", 
                        high_qc.view, self.lock_qc.view
                    );
                    return Ok(());
                }
                info!("Proposal differs from locked blob, but highQC view {} > lockQC view {}, accepting",
                    high_qc.view, self.lock_qc.view);
                // Verify the new proposal with replica since it differs from our lock
                match time::timeout(
                    time::Duration::from_secs(REPLICA_TIMEOUT_SECS),
                    self.replica_client.verify_proposal(node.blob.clone()),
                ).await {
                    Ok(Ok(())) => info!("Proposal verification successful"),
                    Ok(Err(error)) => {
                        error!("Proposal verification failed: {:?}", error);
                        return Ok(());
                    }
                    Err(_) => {
                        error!("Proposal verification timed out after {}s", REPLICA_TIMEOUT_SECS);
                        return Ok(());
                    }
                }
            } else {
                info!("Proposal matches locked blob, skipping replica verification");
            }
        } else {
            match time::timeout(
                time::Duration::from_secs(REPLICA_TIMEOUT_SECS),
                self.replica_client.verify_proposal(node.blob.clone()),
            ).await {
                Ok(Ok(())) => info!("Proposal verification successful"),
                Ok(Err(error)) => {
                    error!("Proposal verification failed: {:?}", error);
                    return Ok(());
                }
                Err(_) => {
                    error!("Proposal verification timed out after {}s", REPLICA_TIMEOUT_SECS);
                    return Ok(());
                }
            }
        }

        // Apply safety and liveness rules
        self.extend(&node, &high_qc)?;
        self.safe_node(&node, &high_qc)?;
        
        self.voted_node = node.clone();
        self.voted_view = view.clone();
        self.persist_voted_state().await;
        self.send_prepare_vote(node.digest()).await?;

        // Try processing buffered PreCommit message
        if let Some((author, pv, qc)) = self.pending_precommit.take() {
            if pv == self.view {
                info!("Processing buffered PreCommit for view {}", pv);
                self.handle_pre_commit(author, pv, qc).await?;
            }
        }
        Ok(())
    }

    fn extend(&self, node: &Node<N, S, D, U, P, V>, high_qc: &QuorumCert<S, D>) -> ConsensusResult<()> {        
        if node.parent != high_qc.node_digest {
            return Err(ConsensusError::InvalidQC(
                format!("expect parent {:?}, got {:?}", high_qc.node_digest, node.parent)
            ));
        }
        Ok(())
    }

    fn safe_node(&self, node: &Node<N, S, D, U, P, V>, high_qc: &QuorumCert<S, D>) -> ConsensusResult<()> {
        if self.lock_qc == QuorumCert::<S, D>::default() {
            debug!("No lock QC (genesis), node is safe");
            return Ok(());
        }

        let high_view = high_qc.view;
        let lock_view = self.lock_qc.view;
        
        // Safety conditions (either must be true):
        // 1. highQC.view > lockQC.view OR
        // 2. node extends lockQC (node's parent equals lockQC's node)
        let higher_view = high_view > lock_view;
        let extends_lock = node.parent == self.lock_qc.node_digest;
        
        if higher_view {
            debug!("Node is safe: higher view ({} > {})", high_view, lock_view);
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

    pub async fn send_prepare_vote(&mut self, node_digest: Digest<S, D>) -> ConsensusResult<()> {
        info!("Sending PrepareVote message");
        let prepare_vote_message = ConsensusMessage::<N, S, D, U, P, V>::new(
            ConsensusMessageType::Prepare,
            self.name,
            self.view.clone(), 
            MessagePayload::<N, S, D, U, P, V>::PrepareVote(node_digest.clone()),
            self.signature_service.clone(),
        ).await;

        match postcard::to_allocvec(&prepare_vote_message) {
            Ok(payload) => {
                let leader = self.leader_elector.get_leader(self.view);
                debug!("Sending PrepareVote {:?} to leader {:?}", node_digest, leader);
                self.network.send(None, payload)?;
                debug!("PrepareVote message sent successfully");
            }
            Err(e) => {
                return Err(ConsensusError::SerializationError(e.to_string()));
            }
        }
        Ok(())
    }

    pub async fn fetch_and_parse_proposal(&self) -> Option<(String, u64)> {
        let result = match time::timeout(
            time::Duration::from_secs(REPLICA_TIMEOUT_SECS),
            self.replica_client.get_proposal(),
        ).await {
            Ok(result) => result,
            Err(_) => {
                error!("get_proposal timed out after {}s", REPLICA_TIMEOUT_SECS);
                return None;
            }
        };
        match result {
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
