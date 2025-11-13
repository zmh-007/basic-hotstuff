use bytes::Bytes;
use crypto::{PublicKey, Signature};
use log::{debug, info, warn};
use crate::{ConsensusError, ConsensusMessage, QuorumCert, consensus::{ConsensusMessageType, MessagePayload, Node, View}, core::Core, error::ConsensusResult};


impl Core {
    pub async fn handle_prepare_vote(&mut self, author: PublicKey, view: View, signature: Signature, node: Node) -> ConsensusResult<()> {
        info!("Received prepare vote for view {:?}", view);
        if view != self.view {
            warn!("Received prepare vote for view {:?}, but current view is {:?}", view, self.view);
            return Ok(());
        }
        if !self.check_is_leader(&view) {
            warn!("Received prepare vote for view {:?}, but self {:?} not the leader", view, self.name);
            return Ok(());
        }

        if let Some(prepare_qc) = self.aggregator.add_prepare_vote(author, view.clone(), signature, node)? {
            debug!("Formed Prepare QC for view {:?}", view);
            self.prepare_qc = prepare_qc.clone();
            self.send_pre_commit(prepare_qc).await?;
        }
        Ok(())
    }

    pub async fn send_pre_commit(&mut self, prepare_qc: QuorumCert) -> ConsensusResult<()> {
        debug!("Sending PreCommit message");
        let prepare_message = ConsensusMessage::new(
            ConsensusMessageType::PreCommit,
            self.name,
            self.view.clone(), 
            MessagePayload::PreCommit(prepare_qc.clone()),
            self.signature_service.clone(),
        ).await;

         match bincode::serialize(&prepare_message) {
                Ok(payload) => {
                 // broadcast the message
                 debug!("Broadcast {:?}", prepare_message);
                 let addresses = self
                      .committee
                      .broadcast_addresses(&self.name)
                      .into_iter()
                      .map(|(_, x)| x)
                      .collect();
                 self.network.broadcast(addresses, Bytes::from(payload)).await;
                 debug!("PreCommit message broadcast successfully");
                 self.handle_pre_commit(self.name, self.view.clone(), prepare_qc).await?;
                }
                Err(e) => {
                 return Err(ConsensusError::SerializationError(e));
                }
          }
        Ok(())
    }

    pub async fn handle_pre_commit(&mut self, author: PublicKey, view: View, prepare_qc: QuorumCert) -> ConsensusResult<()> {
        info!("Received PreCommit for view {:?}", view);
        if view != self.view {
            warn!("Received PreCommit for view {:?}, but current view is {:?}", view, self.view);
            return Ok(());
        }
        if !self.check_from_leader(&view, author) {
            warn!("Received PreCommit for view {:?}, but author {:?} is not the leader", view, author);
            return Ok(());
        }
        if prepare_qc.qc_type != ConsensusMessageType::Prepare {
            warn!("Received PreCommit with invalid QC type: {:?}", prepare_qc.qc_type);
            return Ok(());
        }
        if !self.check_node(&prepare_qc.node) {
            warn!("Received precommit for view {:?}, but node digest {:?} doesn't match voted node digest {:?}", 
                  view, prepare_qc.node.digest(), self.voted_node.digest());
            return Ok(());
        }
        prepare_qc.verify(&self.committee)?;
        self.prepare_qc = prepare_qc.clone();
        self.send_pre_commit_vote(prepare_qc.node).await?;

        Ok(())
    }

    pub async fn send_pre_commit_vote(&mut self, node: Node) -> ConsensusResult<()> {
        debug!("Sending PreCommitVote message");
        let pre_commit_vote_message = ConsensusMessage::new(
            ConsensusMessageType::PreCommit,
            self.name,
            self.view.clone(), 
            MessagePayload::PreCommitVote(node.clone()),
            self.signature_service.clone(),
        ).await;

         match bincode::serialize(&pre_commit_vote_message) {
                Ok(payload) => {
                    // send the message to leader
                    debug!("send precommit vote to leader: {:?}", pre_commit_vote_message);
                    let leader = self.leader_elector.get_leader(&self.view);
                    let address = self
                        .committee
                        .address(&leader)
                        .expect("The leader is not in the committee");
                    self.network.send(address, Bytes::from(payload)).await;
                    debug!("PreCommitVote message sent successfully");
                }
                Err(e) => {
                    return Err(ConsensusError::SerializationError(e));
                }
          }
        Ok(())
    }
}
