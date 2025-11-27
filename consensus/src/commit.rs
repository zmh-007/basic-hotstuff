use crypto::{Digest, PublicKey};
use log::{debug, info, warn};
use crate::{ConsensusError, ConsensusMessage, QuorumCert, consensus::{ConsensusMessageType, MessagePayload, View}, core::Core, error::ConsensusResult};


impl Core {
    pub async fn handle_commit(&mut self, _: PublicKey, view: View, pre_commit_qc: QuorumCert) -> ConsensusResult<()> {
        info!("Received Commit for view {:?}", view);
        if view != self.view {
            warn!("Received Commit for view {:?}, but current view is {:?}", view, self.view);
            return Ok(());
        }
        if pre_commit_qc.qc_type != ConsensusMessageType::PreCommit {
            warn!("Received Commit with invalid QC type: {:?}", pre_commit_qc.qc_type);
            return Ok(());
        }
        if !self.check_node(&pre_commit_qc.node_digest) {
            warn!("Received commit for view {:?}, but node digest {:?} doesn't match voted node digest {:?}", 
                  view, pre_commit_qc.node_digest, self.voted_node.digest());
            return Ok(());
        }
        pre_commit_qc.verify(&self.committee)?;
        self.lock_qc_and_blob(pre_commit_qc.clone());

        self.send_commit_vote(pre_commit_qc.node_digest.clone()).await?;
        Ok(())
    }

    pub async fn send_commit_vote(&mut self, node_digest: Digest) -> ConsensusResult<()> {
        info!("Sending Commit Vote message");
        let commit_vote_message = ConsensusMessage::new(
            ConsensusMessageType::Commit,
            self.name,
            self.view.clone(), 
            MessagePayload::CommitVote(node_digest.clone()),
            self.signature_service.clone(),
        ).await;

         match bincode::serialize(&commit_vote_message) {
                Ok(payload) => {
                    // send the message to leader
                    let leader = self.leader_elector.get_leader(&self.view);
                    debug!("send commit vote {:?} to leader: {:?}", node_digest, leader);
                    self.network.send(None, payload)?;
                    debug!("Commit Vote message sent successfully");
                }
                Err(e) => {
                 return Err(ConsensusError::SerializationError(e));
                }
          }
        Ok(())
    }

    fn lock_qc_and_blob(&mut self, qc: QuorumCert) {
        self.lock_qc = qc.clone();
        self.lock_blob = self.voted_node.blob.clone();
    }
}