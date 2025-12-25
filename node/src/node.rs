// Standard library imports
use tokio::sync::mpsc::{channel, Receiver};

// External crate imports
use log::info;
use zkp::{Scalar, Digest as ZkpDigest, Proof, Vk};
use serde::de::DeserializeOwned;

// Internal crate imports
use consensus::Consensus;
use crypto::SignatureService;
use store::Store;

// Local imports
use crate::config::{Committee, ConfigError, Parameters, Secret, Export as _};

/// The default channel capacity for this module.
pub const CHANNEL_CAPACITY: usize = 1_000;

pub struct Node {
    pub commit: Receiver<String>,
}

impl Node {
    pub async fn new<const N: usize, S: Scalar + 'static, D: ZkpDigest<S> + DeserializeOwned + 'static, P: Proof<S> + DeserializeOwned + 'static, V: Vk<N, S, P> + DeserializeOwned + 'static>(
        committee_file: &str,
        key_file: &str,
        store_path: &str,
        parameters: Option<String>,
    ) -> Result<Self, ConfigError> {
        let (tx_commit, rx_commit) = channel(CHANNEL_CAPACITY);

        // Read configuration files
        info!("Loading node configuration...");
        let committee = Committee::read(committee_file)?;
        let secret = Secret::read(key_file)?;
        let name = secret.name;
        let secret_key = secret.secret;

        // Load parameters (default if not specified)
        let parameters = match parameters {
            Some(filename) => {
                info!("Loading parameters from: {}", filename);
                Parameters::read(&filename)?
            }
            None => {
                info!("Using default parameters");
                Parameters::default()
            }
        };

        // Initialize data store
        info!("Initializing data store at: {}", store_path);
        let store = Store::new(store_path)
            .map_err(|e| ConfigError::ReadError {
                file: store_path.to_string(),
                message: format!("Store initialization failed: {}", e),
            })?;

        // Initialize signature service
        let signature_service = SignatureService::<S, D>::new(secret_key);

        // Start consensus core
        info!("Starting consensus core for node: {}", name);
        Consensus::<N, S, D, P, V>::spawn(
            name,
            committee.consensus,
            parameters.consensus,
            signature_service,
            store.clone(),
            tx_commit,
        );

        info!("Node {} successfully booted and ready", name);
        Ok(Self { commit: rx_commit })
    }

    pub fn print_key_file(filename: &str) -> Result<(), ConfigError> {
        Secret::new().write(filename)
    }

    pub async fn start(&mut self) {
        info!("Node started, waiting for committed blocks...");
        
        loop {
            tokio::select! {
                Some(block) = self.commit.recv() => {
                    info!("Received committed block: {}", block);
                    // TODO: Implement actual block execution logic
                    // This would typically involve:
                    // 1. Parsing the block contents
                    // 2. Executing transactions in order
                    // 3. Updating application state
                    // 4. Reporting execution results
                }
                else => {
                    info!("Consensus commit channel closed, shutting down node");
                    break;
                }
            }
        }
    }
}
