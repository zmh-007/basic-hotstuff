use crypto::PublicKey;
use log::info;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;

pub type Stake = u32;

#[derive(Serialize, Deserialize, Clone)]
pub struct Parameters {
    pub timeout_delay: u64,
    pub propose_delay: u64,
}

impl Default for Parameters {
    fn default() -> Self {
        Self {
            timeout_delay: 5_000,
            propose_delay: 1_000,
        }
    }
}

impl Parameters {
    pub fn log(&self) {
        // NOTE: These log entries are used to compute performance.
        info!("Timeout delay set to {} ms", self.timeout_delay);
        info!("Propose delay set to {} ms", self.propose_delay);
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Authority {
    pub stake: Stake,
    pub address: SocketAddr,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Committee {
    pub authorities: HashMap<PublicKey, Authority>,
}

impl Committee {
    pub fn new(info: Vec<(PublicKey, Stake, SocketAddr)>) -> Self {
        Self {
            authorities: info
                .into_iter()
                .map(|(name, stake, address)| {
                    let authority = Authority { stake, address };
                    (name, authority)
                })
                .collect(),
        }
    }

    pub fn size(&self) -> usize {
        self.authorities.len()
    }

    pub fn stake(&self, name: &PublicKey) -> Stake {
        self.authorities.get(name).map_or_else(|| 0, |x| x.stake)
    }

    pub fn quorum_threshold(&self) -> Stake {
        // If N = 3f + 1 + k (0 <= k < 3)
        // then (2 N + 3) / 3 = 2f + 1 + (2k + 2)/3 = 2f + 1 + k = N - f
        let total_votes: Stake = self.authorities.values().map(|x| x.stake).sum();
        2 * total_votes / 3 + 1
    }

    pub fn address(&self, name: &PublicKey) -> Option<SocketAddr> {
        self.authorities.get(name).map(|x| x.address)
    }

    pub fn broadcast_addresses(&self, myself: &PublicKey) -> Vec<(PublicKey, SocketAddr)> {
        self.authorities
            .iter()
            .filter(|(name, _)| name != &myself)
            .map(|(name, x)| (name.clone(), x.address))
            .collect()
    }
}
