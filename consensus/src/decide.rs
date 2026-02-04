use crypto::{PublicKey};
use log::{info, error};
use tokio::time;
use crate::{QuorumCert, consensus::{ConsensusMessageType, Node, View}, core::Core, error::ConsensusResult, timer::Timer};
use zkp::{Scalar, Digest as ZkpDigest, Proof, Vk, SafeU256};
use serde::de::DeserializeOwned;

impl<const N: usize, S: Scalar, D: ZkpDigest<S> + DeserializeOwned + 'static, U: SafeU256<Scalar=S> + DeserializeOwned + 'static, P: Proof<S> + DeserializeOwned, V: Vk<N, S, P> + DeserializeOwned> Core<N, S, D, U, P, V> {
    pub async fn handle_decide(&mut self, _: PublicKey, view: View<S, D>, commit_qc: QuorumCert<S, D>, node: Node<N, S, D, U, P, V>) -> ConsensusResult<()> {
        info!("Received Decide for view {:?}", view);
        if commit_qc.view.height < self.view.height {
            info!("Ignoring stale Decide for height {} (current: {})", commit_qc.view.height, self.view.height);
            return Ok(());
        }

        if commit_qc.qc_type != ConsensusMessageType::Commit {
            error!("Received decide with invalid QC type: {:?}", commit_qc.qc_type);
            return Ok(());
        }
        
        // Verify that the node digest matches the commit QC
        let node_digest = node.digest();
        if node_digest != commit_qc.node_digest {
            error!("Node digest mismatch: expected {:?}, got {:?}", commit_qc.node_digest, node_digest);
            return Ok(());
        }
        
        commit_qc.verify(&self.committee)?;
        if let Err(e) = self.tx_commit.send(node.blob.clone()).await {
            error!("Failed to send block through the commit channel: {}", e);
        }
        if let Err(e) = self.replica_client.submit_next_block(node.blob.clone()).await {
            error!("Failed to submit next block: {:?}", e);
        }

        time::sleep(time::Duration::from_millis(self.parameters.propose_delay)).await;
        let new_height = commit_qc.view.height + 1;
        self.aggregator.cleanup(new_height);
        self.unlock_blob().await;
        self.view.height = new_height;
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