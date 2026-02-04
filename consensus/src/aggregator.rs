use crate::QuorumCert;
use crate::config::{Committee, Stake};
use crate::consensus::{View};
use crate::error::{ConsensusError, ConsensusResult};
use std::collections::{HashMap, HashSet};
use crypto::{PublicKey};
use zkp::{Scalar, Digest as ZkpDigest};

pub struct Aggregator<S: Scalar, D: ZkpDigest<S>> {
    committee: Committee,
    new_view_aggregators: HashMap<View<S, D>, Box<NVMaker<S, D>>>,
}

impl<S: Scalar, D: ZkpDigest<S>> Aggregator<S, D> {
    /// Maximum number of future heights to accept NewView messages for
    const MAX_FUTURE_HEIGHTS: u64 = 10;

    pub fn new(committee: Committee) -> Self {
        Self {
            committee,
            new_view_aggregators: HashMap::new(),
        }
    }

    pub fn add_new_view(&mut self, current_height: u64, author: PublicKey, view: View<S, D>, qc: QuorumCert<S, D>) -> ConsensusResult<Option<QuorumCert<S, D>>> {
        // Reject views too far in the future to prevent memory exhaustion attack
        if view.height > current_height + Self::MAX_FUTURE_HEIGHTS {
            return Err(ConsensusError::ViewTooFarInFuture(view.height, current_height));
        }
        
        // Silently ignore stale views (already committed heights)
        if view.height < current_height {
            return Ok(None);
        }

        // Add the new vote to our aggregator and see if we have a QC.
        self.new_view_aggregators
            .entry(view)
            .or_insert_with(|| Box::new(NVMaker::new()))
            .append(author, qc, &self.committee)
    }

    /// Cleanup stale views that are below the current height.
    /// This preserves aggregators for current and future views.
    pub fn cleanup(&mut self, current_height: u64) {
        self.new_view_aggregators.retain(|view, _| view.height >= current_height);
    }
}

struct NVMaker<S: Scalar, D: ZkpDigest<S>> {
    weight: Stake,
    votes: Vec<(PublicKey, QuorumCert<S, D>)>,
    used: HashSet<PublicKey>,
}

impl<S: Scalar, D: ZkpDigest<S>> NVMaker<S, D> {
    pub fn new() -> Self {
        Self {
            weight: 0,
            votes: Vec::new(),
            used: HashSet::new(),
        }
    }

    pub fn append(
        &mut self,
        author: PublicKey,
        qc: QuorumCert<S, D>,
        committee: &Committee,
    ) -> ConsensusResult<Option<QuorumCert<S, D>>> {
        // Ensure it is the first time this authority votes.
        crate::ensure!(
            self.used.insert(author),
            ConsensusError::AuthorityReuse(author)
        );

        // Add the QC to the accumulator.
        self.votes.push((author.clone(), qc.clone()));
        self.weight += committee.stake(&author);
        if self.weight >= committee.quorum_threshold() {
            self.weight = 0;
            
            // Find the QC with the highest view (first by height, then by round)
            let highest_qc = self.votes
                .iter()
                .map(|(_, qc)| qc)
                .max_by_key(|qc| (qc.view.height, qc.view.round))
                .unwrap()
                .clone();
            
            return Ok(Some(highest_qc));
        }
        Ok(None)
    }
}
