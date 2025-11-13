use bytes::Bytes;
use crypto::{PublicKey, Signature};
use log::{debug, info, warn};
use crate::{ConsensusError, ConsensusMessage, QuorumCert, consensus::{ConsensusMessageType, MessagePayload, Node, View}, core::Core, error::ConsensusResult};


impl Core {
    pub async fn handle_pre_commit_vote(&mut self, author: PublicKey, view: View, signature: Signature, node: Node) -> ConsensusResult<()> {
        info!("Received pre commit vote for view {:?}", view);
        if view != self.view {
            warn!("Received pre commit vote for view {:?}, but current view is {:?}", view, self.view);
            return Ok(());
        }
        if !self.check_is_leader(&view) {
            warn!("Received pre commit vote for view {:?}, but self {:?} not the leader", view, self.name);
            return Ok(());
        }

        if let Some(pre_commit_qc) = self.aggregator.add_pre_commit_vote(author, view.clone(), signature, node)? {
            debug!("Formed PreCommit QC for view {:?}", view);
            self.lock_qc_and_blob(pre_commit_qc.clone());
            self.send_commit(pre_commit_qc).await?;
        }
        Ok(())
    }

    pub async fn send_commit(&mut self, pre_commit_qc: QuorumCert) -> ConsensusResult<()> {
        debug!("Sending Commit message");
        let commit_message = ConsensusMessage::new(
            ConsensusMessageType::Commit,
            self.name,
            self.view.clone(), 
            MessagePayload::Commit(pre_commit_qc.clone()),
            self.signature_service.clone(),
        ).await;

         match bincode::serialize(&commit_message) {
                Ok(payload) => {
                 // broadcast the message
                 debug!("Broadcast commit message{:?}", commit_message);
                 let addresses = self
                      .committee
                      .broadcast_addresses(&self.name)
                      .into_iter()
                      .map(|(_, x)| x)
                      .collect();
                 self.network.broadcast(addresses, Bytes::from(payload)).await;
                 debug!("Commit message broadcast successfully");
                 self.handle_commit(self.name, self.view.clone(), pre_commit_qc.clone()).await?;
                }
                Err(e) => {
                 return Err(ConsensusError::SerializationError(e));
                }
          }
        Ok(())
    }

    pub async fn handle_commit(&mut self, author: PublicKey, view: View, pre_commit_qc: QuorumCert) -> ConsensusResult<()> {
        info!("Received Commit for view {:?}", view);
        if view != self.view {
            warn!("Received Commit for view {:?}, but current view is {:?}", view, self.view);
            return Ok(());
        }
        if !self.check_from_leader(&view, author) {
            warn!("Received Commit for view {:?} from {:?}, but not from leader", view, author);
            return Ok(());
        }
        if pre_commit_qc.qc_type != ConsensusMessageType::PreCommit {
            warn!("Received Commit with invalid QC type: {:?}", pre_commit_qc.qc_type);
            return Ok(());
        }
        pre_commit_qc.verify(&self.committee)?;
        self.lock_qc_and_blob(pre_commit_qc.clone());

        self.send_commit_vote(pre_commit_qc.node.clone()).await?;
        Ok(())
    }

    pub async fn send_commit_vote(&mut self, node: Node) -> ConsensusResult<()> {
        debug!("Sending Commit Vote message");
        let commit_vote_message = ConsensusMessage::new(
            ConsensusMessageType::Commit,
            self.name,
            self.view.clone(), 
            MessagePayload::CommitVote(node.clone()),
            self.signature_service.clone(),
        ).await;

         match bincode::serialize(&commit_vote_message) {
                Ok(payload) => {
                    // send the message to leader
                    debug!("send commit vote to leader: {:?}", commit_vote_message);
                    let leader = self.leader_elector.get_leader(&self.view);
                    let address = self
                        .committee
                        .address(&leader)
                        .expect("The leader is not in the committee");
                    self.network.send(address, Bytes::from(payload)).await;
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
        self.lock_blob = qc.node.blob.clone();
    }
}