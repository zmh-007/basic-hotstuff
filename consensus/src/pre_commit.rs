use crypto::{Digest, PublicKey};
use log::{debug, info, error};
use crate::{ConsensusError, ConsensusMessage, QuorumCert, consensus::{ConsensusMessageType, MessagePayload, View}, core::Core, error::ConsensusResult};
use zkp::{Scalar, Digest as ZkpDigest, Proof, Vk};

impl<const N: usize, S: Scalar, D: ZkpDigest<S> + 'static, P: Proof<S>, V: Vk<N, S, P>> Core<N, S, D, P, V> {
    pub async fn handle_pre_commit(&mut self, _: PublicKey, view: View<S, D>, prepare_qc: QuorumCert<S, D>) -> ConsensusResult<()> {
        info!("Received PreCommit for view {:?}", view);
        if view != self.view {
            error!("Received PreCommit for view {:?}, but current view is {:?}", view, self.view);
            return Ok(());
        }
        if prepare_qc.qc_type != ConsensusMessageType::Prepare {
            error!("Received PreCommit with invalid QC type: {:?}", prepare_qc.qc_type);
            return Ok(());
        }
        if !self.check_node(&prepare_qc.node_digest) {
            error!("Received precommit for view {:?}, but node digest {:?} doesn't match voted node digest {:?}", 
                  view, prepare_qc.node_digest, self.voted_node.digest());
            return Ok(());
        }
        prepare_qc.verify(&self.committee)?;
        self.prepare_qc = prepare_qc.clone();
        self.persist_prepare_qc().await;
        self.send_pre_commit_vote(prepare_qc.node_digest.clone()).await?;

        Ok(())
    }

    pub async fn send_pre_commit_vote(&mut self, node_digest: Digest<S, D>) -> ConsensusResult<()> {
        info!("Sending PreCommitVote message");
        let pre_commit_vote_message = ConsensusMessage::<N, S, D, P, V>::new(
            ConsensusMessageType::PreCommit,
            self.name,
            self.view.clone(), 
            MessagePayload::<N, S, D, P, V>::PreCommitVote(node_digest.clone()),
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
