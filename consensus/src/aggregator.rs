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
    pub fn new(committee: Committee) -> Self {
        Self {
            committee,
            new_view_aggregators: HashMap::new(),
        }
    }

    pub fn add_new_view(&mut self, author: PublicKey, view: View<S, D>, qc: QuorumCert<S, D>) -> ConsensusResult<Option<QuorumCert<S, D>>> {
        // TODO: A bad node may make us run out of memory by sending many votes
        // with different view numbers.

        // Add the new vote to our aggregator and see if we have a QC.
        self.new_view_aggregators
            .entry(view)
            .or_insert_with(|| Box::new(NVMaker::new()))
            .append(author, qc, &self.committee)
    }

    pub fn cleanup(&mut self) {
        self.new_view_aggregators.clear();
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
