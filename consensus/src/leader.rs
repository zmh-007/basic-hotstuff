use crypto::PublicKey;
use crate::{config::Committee, consensus::View};

pub type LeaderElector = RRLeaderElector;

pub struct RRLeaderElector {
    committee: Committee,
}

impl RRLeaderElector {
    pub fn new(committee: Committee) -> Self {
        Self { committee }
    }

    pub fn get_leader(&self, view: &View) -> PublicKey {
        let mut keys: Vec<_> = self.committee.authorities.keys().cloned().collect();
        keys.sort();
        keys[(view.height + view.round) as usize % self.committee.size()]
    }
}
