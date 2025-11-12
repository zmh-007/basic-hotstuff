use bytes::Bytes;
use crypto::{PublicKey, Signature};
use log::{debug, warn};
use tokio::time;
use crate::{ConsensusError, ConsensusMessage, QuorumCert, consensus::{ConsensusMessageType, MessagePayload, Node}, core::Core, error::ConsensusResult};


impl Core {
    pub async fn handle_commit_vote(&mut self, author: PublicKey, view: u64, signature: Signature, node: Node) -> ConsensusResult<()> {
        debug!("Received commit vote for view {:?}", view);
        if view < self.view {
            return Ok(());
        }
        if !self.check_is_leader(view) {
            warn!("Received commit vote for view {:?}, but self {:?} not the leader", view, self.name);
            return Ok(());
        }

        if let Some(commit_qc) = self.aggregator.add_commit_vote(author, view, signature, node)? {
            debug!("Formed Commit QC for view {:?}", view);
            self.send_decide(commit_qc).await?;
        }
        Ok(())
    }

    pub async fn send_decide(&mut self, commit_qc: QuorumCert) -> ConsensusResult<()> {
        debug!("Sending Decide message");
        let decide_message = ConsensusMessage::new(
            ConsensusMessageType::Decide,
            self.name,
            self.view, 
            MessagePayload::Decide(commit_qc.clone()),
            self.signature_service.clone(),
        ).await;

         match bincode::serialize(&decide_message) {
                Ok(payload) => {
                 // broadcast the message
                 debug!("Broadcast decide message{:?}", decide_message);
                 let addresses = self
                      .committee
                      .broadcast_addresses(&self.name)
                      .into_iter()
                      .map(|(_, x)| x)
                      .collect();
                 self.network.broadcast(addresses, Bytes::from(payload)).await;
                 debug!("Decide message broadcast successfully");
                 self.handle_decide(self.name, self.view, commit_qc.clone()).await?;
                }
                Err(e) => {
                 return Err(ConsensusError::SerializationError(e));
                }
          }
        Ok(())
    }

    pub async fn handle_decide(&mut self, author: PublicKey, view: u64, commit_qc: QuorumCert) -> ConsensusResult<()> {
        debug!("Received Decide for view {:?}", view);
        if view < self.view {
            return Ok(());
        }
        if !self.check_from_leader(view, author) {
            warn!("Received decide for view {:?} from {:?}, but not from leader", view, author);
            return Ok(());
        }
        if commit_qc.qc_type != ConsensusMessageType::Commit {
            warn!("Received decide with invalid QC type: {:?}", commit_qc.qc_type);
            return Ok(());
        }
        commit_qc.verify(&self.committee)?;
        if let Err(e) = self.tx_commit.send(commit_qc.node.blob.clone()).await {
            warn!("Failed to send block through the commit channel: {}", e);
        }

        time::sleep(time::Duration::from_millis(self.parameters.propose_delay)).await;
        self.start_new_view().await;
        Ok(())
    }
}