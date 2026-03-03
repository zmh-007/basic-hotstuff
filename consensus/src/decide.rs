use crypto::{PublicKey};
use hex::decode;
use l0::{Blk, Wp};
use log::{info, error};
use tokio::time;

/// Timeout for replica RPC calls (in seconds)
const REPLICA_TIMEOUT_SECS: u64 = 10;
use crate::{QuorumCert, consensus::{ConsensusMessageType, Node, View}, core::Core, error::ConsensusResult, timer::Timer};
use zkp::{Scalar, Digest as ZkpDigest, Proof, Vk, SafeU256, mockimpl::MockSignature, AsScalars};
use serde::de::DeserializeOwned;

impl<const N: usize, S: Scalar, D: ZkpDigest<S> + AsScalars + DeserializeOwned + 'static, U: SafeU256<Scalar=S> + DeserializeOwned + 'static, P: Proof<S> + DeserializeOwned, V: Vk<N, S, P> + DeserializeOwned> Core<N, S, D, U, P, V> {
    pub async fn handle_decide(&mut self, author: PublicKey, view: View, commit_qc: QuorumCert<S, D>, node: Node<N, S, D, U, P, V>, wp_blk: String) -> ConsensusResult<()> {
        info!("Received Decide for view {:?}", view);
        if view != self.view {
            error!("Received Decide for view {:?}, but current view is {:?}", view, self.view);
            return Ok(());
        }
        // Buffer Decide if Commit hasn't been processed yet for this view
        if self.lock_qc.view < view {
            info!("Decide for view {} arrived before Commit completed, buffering", view);
            self.pending_decide = Some((author, view, commit_qc, node, wp_blk));
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

        // Verify that node matches what the QC committed
        if node.digest() != commit_qc.node_digest {
            error!("Decide node digest {:?} doesn't match commit QC node digest {:?}",
                  node.digest(), commit_qc.node_digest);
            return Ok(());
        }

        // Verify that wp_blk contains the same block as node.blob
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

        let blob_stripped = node.blob.strip_prefix("0x").unwrap_or(&node.blob);
        let blob_blk_hash = match decode(blob_stripped) {
            Ok(bytes) => {
                match postcard::from_bytes::<Blk<N, S, MockSignature, D, U, P, V>>(&bytes) {
                    Ok(blk) => blk.hash(),
                    Err(e) => {
                        error!("Failed to deserialize node.blob: {}", e);
                        return Ok(());
                    }
                }
            }
            Err(e) => {
                error!("Failed to decode node.blob hex: {}", e);
                return Ok(());
            }
        };
        if wp_val_hash != blob_blk_hash {
            error!("wp_blk.val hash does not match node.blob hash");
            return Ok(());
        }

        if let Err(e) = self.tx_commit.send(wp_blk.clone()).await {
            error!("Failed to send block through the commit channel: {}", e);
        }
        match time::timeout(
            time::Duration::from_secs(REPLICA_TIMEOUT_SECS),
            self.replica_client.submit_next_block(wp_blk),
        ).await {
            Ok(Ok(())) => {},
            Ok(Err(e)) => error!("Failed to submit next block: {:?}", e),
            Err(_) => error!("submit_next_block timed out after {}s", REPLICA_TIMEOUT_SECS),
        }

        time::sleep(time::Duration::from_millis(self.parameters.propose_delay)).await;
        self.unlock_blob().await;
        self.consecutive_timeouts = 0;
        // Reset timer to original timeout
        self.timer = Timer::new(self.parameters.timeout_delay);
        self.start_new_view(view + 1).await;
        Ok(())
    }

    async fn unlock_blob(&mut self) {
        self.lock_blob = String::new();
        self.persist_lock_blob().await;
    }
}