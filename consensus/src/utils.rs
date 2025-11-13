use crypto::{Digest, PublicKey, Signature};

use crate::{ConsensusError, consensus::View, core::Core, error::ConsensusResult};

impl Core {
    pub fn check_is_leader(&self, view: &View) -> bool {
        let leader = self.leader_elector.get_leader(view);
        leader == self.name
    }

    pub fn check_from_leader(&self, view: &View, author: PublicKey) -> bool {
        let leader = self.leader_elector.get_leader(view);
        leader == author
    }
}

pub fn verify_signature(digest: &Digest, author: &PublicKey, sig: &Signature) -> ConsensusResult<()>{
    let dst = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
    let signature = blst::min_pk::Signature::from_bytes(&sig.0).expect("Invalid signature bytes");
    let pk = blst::min_pk::PublicKey::from_bytes(&author.0).expect("Invalid public key bytes");
    let err = signature.verify(true, &digest.to_vec(), dst, &[], &pk, true);
    if err != blst::BLST_ERROR::BLST_SUCCESS {
        return Err(ConsensusError::InvalidSignature(author.to_string()));
    }
    Ok(())
}