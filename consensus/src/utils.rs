use crypto::{Digest, PublicKey, Signature};

use crate::{ConsensusError, consensus::{Node, View}, core::Core, error::ConsensusResult};
use zkp::{Scalar, Digest as ZkpDigest, Proof, Vk};

impl<const N: usize, S: Scalar, D: ZkpDigest<S> + 'static, P: Proof<S>, V: Vk<N, S, P>> Core<N, S, D, P, V> {
    pub fn check_is_leader(&self, view: &View<S, D>) -> bool {
        let leader = self.leader_elector.get_leader(view);
        leader == self.name
    }

    pub fn check_node(&self, node_digest: &Digest<S, D>) -> bool {
        self.voted_node != Node::<N, S, D, P, V>::default() && self.voted_node.digest() == *node_digest
    }
}

pub fn verify_signature(digest: &[u8], author: &PublicKey, sig: &Signature) -> ConsensusResult<()>{
    let dst = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
    let signature = blst::min_pk::Signature::from_bytes(&sig.0)
        .map_err(|_| ConsensusError::InvalidSignature("Invalid signature bytes".to_string()))?;
    let pk = blst::min_pk::PublicKey::from_bytes(&author.0)
        .map_err(|_| ConsensusError::InvalidSignature("Invalid public key bytes".to_string()))?;
    let err = signature.verify(true, digest, dst, &[], &pk, true);
    if err != blst::BLST_ERROR::BLST_SUCCESS {
        return Err(ConsensusError::InvalidSignature(author.to_string()));
    }
    Ok(())
}