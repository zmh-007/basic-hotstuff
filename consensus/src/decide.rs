use crypto::{PublicKey};
use log::{info, error};
use tokio::time;
use crate::{QuorumCert, consensus::{ConsensusMessageType, View}, core::Core, error::ConsensusResult, timer::Timer};


impl Core {
    pub async fn handle_decide(&mut self, _: PublicKey, view: View, commit_qc: QuorumCert, wp_blk: String) -> ConsensusResult<()> {
        info!("Received Decide for view {:?}", view);
        if commit_qc.qc_type != ConsensusMessageType::Commit {
            error!("Received decide with invalid QC type: {:?}", commit_qc.qc_type);
            return Ok(());
        }
        commit_qc.verify(&self.committee)?;
        if let Err(e) = self.tx_commit.send(wp_blk.clone()).await {
            error!("Failed to send block through the commit channel: {}", e);
        }
        if let Err(e) = self.replica_client.submit_next_block(wp_blk.clone()).await {
            error!("Failed to submit next block: {:?}", e);
        }

        time::sleep(time::Duration::from_millis(self.parameters.propose_delay)).await;
        self.aggregator.cleanup();
        self.unlock_blob().await;
        self.view.height = commit_qc.view.height + 1;
        self.consecutive_timeouts = 0;
        // Reset timer to original timeout
        self.timer = Timer::new(self.parameters.timeout_delay);
        self.start_new_round(0).await;
        Ok(())
    }

    async fn unlock_blob(&mut self) {
        self.lock_blob = String::new();
        self.persist_lock_blob().await;
    }
}