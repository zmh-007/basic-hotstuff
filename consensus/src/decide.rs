use crypto::{PublicKey};
use hex::decode;
use l0::{Blk, Wp};
use log::{info, error};
use tokio::time;
use crate::{QuorumCert, consensus::{ConsensusMessageType, View}, core::Core, error::ConsensusResult, timer::Timer};
use zkp::{Scalar, Digest as ZkpDigest, Proof, Vk, SafeU256, mockimpl::MockSignature, AsScalars};
use serde::de::DeserializeOwned;

impl<const N: usize, S: Scalar, D: ZkpDigest<S> + AsScalars + DeserializeOwned + 'static, U: SafeU256<Scalar=S> + DeserializeOwned + 'static, P: Proof<S> + DeserializeOwned, V: Vk<N, S, P> + DeserializeOwned> Core<N, S, D, U, P, V> {
    pub async fn handle_decide(&mut self, _: PublicKey, view: View<S, D>, commit_qc: QuorumCert<S, D>, wp_blk: String) -> ConsensusResult<()> {
        info!("Received Decide for view {:?}", view);
        if view != self.view {
            error!("Received Decide for view {:?}, but current view is {:?}", view, self.view);
            return Ok(());
        }
        if commit_qc.qc_type != ConsensusMessageType::Commit {
            error!("Received decide with invalid QC type: {:?}", commit_qc.qc_type);
            return Ok(());
        }
        if commit_qc.view != view {
            error!("Decide QC view mismatch: expected {:?}, got {:?}", view, commit_qc.view);
            return Ok(());
        }
        commit_qc.verify(&self.committee)?;
        
        // Verify that the commit QC matches the node we voted for
        if !self.check_node(&commit_qc.node_digest) {
            error!("Received Decide for view {:?}, but node digest {:?} doesn't match voted node digest {:?}", 
                  view, commit_qc.node_digest, self.voted_node.digest());
            return Ok(());
        }
        
        let wp_blk_stripped = wp_blk.strip_prefix("0x").unwrap_or(&wp_blk);
        let wp_bytes = match decode(wp_blk_stripped) {
            Ok(bytes) => bytes,
            Err(e) => {
                error!("Failed to decode wp_blk hex: {}", e);
                return Ok(());
            }
        };
        let wp: Wp<N, S, MockSignature, D, U, P, V> = match postcard::from_bytes(&wp_bytes) {
            Ok(wp) => wp,
            Err(e) => {
                error!("Failed to deserialize wp_blk: {}", e);
                return Ok(());
            }
        };
        let wp_val_hash = wp.val.hash();
        
        // Deserialize voted_node.blob to get its Blk hash
        let voted_blob_stripped = self.voted_node.blob.strip_prefix("0x").unwrap_or(&self.voted_node.blob);
        let voted_blk_hash = match decode(voted_blob_stripped) {
            Ok(bytes) => {
                match postcard::from_bytes::<Blk<N, S, MockSignature, D, U, P, V>>(&bytes) {
                    Ok(blk) => blk.hash(),
                    Err(e) => {
                        error!("Failed to deserialize voted_node.blob: {}", e);
                        return Ok(());
                    }
                }
            }
            Err(e) => {
                error!("Failed to decode voted_node.blob hex: {}", e);
                return Ok(());
            }
        };
        if wp_val_hash != voted_blk_hash {
            error!("wp_blk.val hash does not match voted_node.blob hash");
            return Ok(());
        }

        if let Err(e) = self.tx_commit.send(wp_blk.clone()).await {
            error!("Failed to send block through the commit channel: {}", e);
        }
        if let Err(e) = self.replica_client.submit_next_block(wp_blk).await {
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