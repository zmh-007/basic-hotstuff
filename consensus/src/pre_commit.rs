use crypto::{Digest, PublicKey};
use log::{debug, info, warn};
use crate::{ConsensusError, ConsensusMessage, QuorumCert, consensus::{ConsensusMessageType, MessagePayload, View}, core::Core, error::ConsensusResult};


impl Core {
    pub async fn handle_pre_commit(&mut self, _: PublicKey, view: View, prepare_qc: QuorumCert) -> ConsensusResult<()> {
        info!("Received PreCommit for view {:?}", view);
        if view != self.view {
            warn!("Received PreCommit for view {:?}, but current view is {:?}", view, self.view);
            return Ok(());
        }
        if prepare_qc.qc_type != ConsensusMessageType::Prepare {
            warn!("Received PreCommit with invalid QC type: {:?}", prepare_qc.qc_type);
            return Ok(());
        }
        if !self.check_node(&prepare_qc.node_digest) {
            warn!("Received precommit for view {:?}, but node digest {:?} doesn't match voted node digest {:?}", 
                  view, prepare_qc.node_digest, self.voted_node.digest());
            return Ok(());
        }
        prepare_qc.verify(&self.committee)?;
        self.prepare_qc = prepare_qc.clone();
        self.send_pre_commit_vote(prepare_qc.node_digest.clone()).await?;

        Ok(())
    }

    pub async fn send_pre_commit_vote(&mut self, node_digest: Digest) -> ConsensusResult<()> {
        info!("Sending PreCommitVote message");
        let pre_commit_vote_message = ConsensusMessage::new(
            ConsensusMessageType::PreCommit,
            self.name,
            self.view.clone(), 
            MessagePayload::PreCommitVote(node_digest.clone()),
            self.signature_service.clone(),
        ).await;

         match bincode::serialize(&pre_commit_vote_message) {
                Ok(payload) => {
                    // send the message to leader
                    let leader = self.leader_elector.get_leader(&self.view);
                    debug!("send precommit vote {:?} to leader: {:?}", node_digest, leader);
                    self.network.send(None, payload)?;
                    debug!("PreCommitVote message sent successfully");
                }
                Err(e) => {
                    return Err(ConsensusError::SerializationError(e));
                }
          }
        Ok(())
    }
}
