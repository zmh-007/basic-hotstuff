use crypto::{PublicKey};
use log::{info, warn};
use tokio::time;
use crate::{QuorumCert, consensus::{ConsensusMessageType, View}, core::Core, error::ConsensusResult};


impl Core {
    pub async fn handle_decide(&mut self, author: PublicKey, view: View, commit_qc: QuorumCert) -> ConsensusResult<()> {
        info!("Received Decide for view {:?}", view);

        if !self.check_from_leader(&view, author) {
            warn!("Received decide for view {:?} from {:?}, but not from leader", view, author);
            return Ok(());
        }
        if commit_qc.qc_type != ConsensusMessageType::Commit {
            warn!("Received decide with invalid QC type: {:?}", commit_qc.qc_type);
            return Ok(());
        }
        commit_qc.verify(&self.committee)?;
        if let Err(e) = self.tx_commit.send(commit_qc.node_digest.clone()).await {
            warn!("Failed to send block through the commit channel: {}", e);
        }

        time::sleep(time::Duration::from_millis(self.parameters.propose_delay)).await;
        self.aggregator.cleanup();
        self.unlock_blob();
        self.view.height = commit_qc.view.height + 1;
        self.start_new_round(0).await;
        Ok(())
    }

    fn unlock_blob(&mut self) {
        self.lock_blob = String::new();
    }
}