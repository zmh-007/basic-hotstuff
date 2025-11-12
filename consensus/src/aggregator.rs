use crate::QuorumCert;
use crate::config::{Committee, Stake};
use crate::consensus::{ConsensusMessageType, Node, View};
use crate::error::{ConsensusError, ConsensusResult};
use std::collections::{HashMap, HashSet};
use crypto::{Digest, PublicKey, Signature};

pub struct Aggregator {
    committee: Committee,
    new_view_aggregators: HashMap<View, Box<NVMaker>>,
    prepare_aggregators: HashMap<View, HashMap<Digest, Box<QCMaker>>>,
    pre_commit_aggregators: HashMap<View, HashMap<Digest, Box<QCMaker>>>,
    commit_aggregators: HashMap<View, HashMap<Digest, Box<QCMaker>>>,
}

impl Aggregator {
    pub fn new(committee: Committee) -> Self {
        Self {
            committee,
            new_view_aggregators: HashMap::new(),
            prepare_aggregators: HashMap::new(),
            pre_commit_aggregators: HashMap::new(),
            commit_aggregators: HashMap::new(),
        }
    }

    pub fn add_new_view(&mut self, author: PublicKey, view: View, qc: QuorumCert) -> ConsensusResult<Option<QuorumCert>> {
        // TODO: A bad node may make us run out of memory by sending many votes
        // with different view numbers.

        // Add the new vote to our aggregator and see if we have a QC.
        self.new_view_aggregators
            .entry(view)
            .or_insert_with(|| Box::new(NVMaker::new()))
            .append(author, qc, &self.committee)
    }

    pub fn add_prepare_vote(&mut self, author: PublicKey, view: View, signature: Signature, node: Node) -> ConsensusResult<Option<QuorumCert>> {
        // TODO: A bad node may make us run out of memory by sending many timeouts
        // with different round numbers or different digests.

        self.prepare_aggregators
            .entry(view)
            .or_insert_with(HashMap::new)
            .entry(node.digest())
            .or_insert_with(|| Box::new(QCMaker::new()))
            .append(author, view, signature, &self.committee, node, ConsensusMessageType::Prepare)
    }

    pub fn add_pre_commit_vote(&mut self, author: PublicKey, view: View, signature: Signature, node: Node) -> ConsensusResult<Option<QuorumCert>> {
        // TODO: A bad node may make us run out of memory by sending many timeouts
        // with different round numbers or different digests.

        self.pre_commit_aggregators
            .entry(view)
            .or_insert_with(HashMap::new)
            .entry(node.digest())
            .or_insert_with(|| Box::new(QCMaker::new()))
            .append(author, view, signature, &self.committee, node, ConsensusMessageType::PreCommit)
    }

    pub fn add_commit_vote(&mut self, author: PublicKey, view: View, signature: Signature, node: Node) -> ConsensusResult<Option<QuorumCert>> {
        // TODO: A bad node may make us run out of memory by sending many timeouts
        // with different round numbers or different digests.

        self.commit_aggregators
            .entry(view)
            .or_insert_with(HashMap::new)
            .entry(node.digest())
            .or_insert_with(|| Box::new(QCMaker::new()))
            .append(author, view, signature, &self.committee, node, ConsensusMessageType::Commit)
    }

    pub fn cleanup(&mut self, view: View) {
        self.new_view_aggregators.retain(|k, _| *k >= view);
        self.prepare_aggregators.retain(|k, _| *k >= view);
        self.pre_commit_aggregators.retain(|k, _| *k >= view);
        self.commit_aggregators.retain(|k, _| *k >= view);
    }
}

struct QCMaker {
    weight: Stake,
    votes: Vec<(PublicKey, Signature)>,
    used: HashSet<PublicKey>,
}

impl QCMaker {
    pub fn new() -> Self {
        Self {
            weight: 0,
            votes: Vec::new(),
            used: HashSet::new(),
        }
    }

    /// Try to append a signature to a quorum.
    pub fn append(&mut self, author: PublicKey, view: View, signature: Signature, committee: &Committee, node: Node, qc_type: ConsensusMessageType) -> ConsensusResult<Option<QuorumCert>> {
        // Ensure it is the first time this authority votes.
        crate::ensure!(
            self.used.insert(author),
            ConsensusError::AuthorityReuse(author)
        );

        self.votes.push((author.clone(), signature.clone()));
        self.weight += committee.stake(&author);
        if self.weight >= committee.quorum_threshold() {
            self.weight = 0;
            let prepare_qc = QuorumCert {
                qc_type,
                view,
                node: node.clone(),
                signatures: self.votes.clone(),
            };
            return Ok(Some(prepare_qc));
        }
        Ok(None)
    }
}

struct NVMaker {
    weight: Stake,
    votes: Vec<(PublicKey, QuorumCert)>,
    used: HashSet<PublicKey>,
}

impl NVMaker {
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
        qc: QuorumCert,
        committee: &Committee,
    ) -> ConsensusResult<Option<QuorumCert>> {
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
            
            // Find the QC with the highest view
            let highest_qc = self.votes
                .iter()
                .map(|(_, qc)| qc)
                .max_by_key(|qc| qc.view)
                .unwrap()
                .clone();
            
            return Ok(Some(highest_qc));
        }
        Ok(None)
    }
}
