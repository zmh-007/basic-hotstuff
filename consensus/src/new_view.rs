use crate::consensus::{ConsensusMessage, ConsensusMessageType, MessagePayload, QuorumCert};
use crate::core::Core;
use crate::error::ConsensusResult;
use bytes::Bytes;
use crypto::{PublicKey};
use log::{debug, warn};
use crate::{ConsensusError};

impl Core {
    /// Send NewView message with current PrepareQC
    pub async fn send_new_view(&mut self) -> ConsensusResult<()> {
        debug!("Sending NewView message");
        // Get the current PrepareQC
        let prepare_qc = self.prepare_qc.clone();
        
        // Create the NewView message with current view, high QC and signature service
        let new_view_message = ConsensusMessage::new(
            ConsensusMessageType::NewView,
            self.name,
            self.view, 
            MessagePayload::NewView(prepare_qc.clone()),
            self.signature_service.clone(),
        ).await;
        
        // Serialize the message
        match bincode::serialize(&new_view_message) {
            Ok(payload) => {
                // send the message
                let leader = self.leader_elector.get_leader(self.view);
                if leader == self.name {
                    self.handle_new_view(self.name, self.view, prepare_qc.clone()).await?;
                } else {
                    debug!("Sending {:?} to {}", new_view_message, leader);
                    let address = self
                        .committee
                        .address(&leader)
                        .expect("The next leader is not in the committee");
                    self.network.send(address, Bytes::from(payload)).await;
                }
                debug!("NewView message sent successfully");
            }
            Err(e) => {
                return Err(ConsensusError::SerializationError(e));
            }
        }
        Ok(())
    }

    pub async fn handle_new_view(&mut self, author: PublicKey, view: u64, prepare_qc: QuorumCert) -> ConsensusResult<()> {
        debug!("Received NewView for view {:?}", view);
        if view < self.view {
            return Ok(());
        }
        if !self.check_is_leader(view) {
            warn!("Received NewView for view {:?}, but {:?} not the leader", view, self.name);
            return Ok(());
        }
        if prepare_qc.qc_type != ConsensusMessageType::Prepare {
            warn!("Received NewView with invalid QC type: {:?}", prepare_qc.qc_type);
            return Ok(());
        }
        if prepare_qc != QuorumCert::default() {
            prepare_qc.verify(&self.committee)?;
        }
        
        // Try to add the new view to aggregator
        if let Some(high_qc) = self.aggregator.add_new_view(author, view, prepare_qc)? {
            // Threshold reached, we have enough NewView messages
            debug!("NewView threshold reached for view {:?}, got high QC with view {:?}", 
                   view, high_qc.view);
            
            // As the leader, we can now start the prepare phase
            self.send_prepare(high_qc).await?;
        }
        Ok(())
    }
}
