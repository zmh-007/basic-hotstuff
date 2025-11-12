use crate::config::Export as _;
use crate::config::{Committee, ConfigError, Parameters, Secret};
use log::{info};
use store::Store;
use tokio::sync::mpsc::{channel, Receiver};
use crypto::{Digest, SignatureService};
use consensus::Consensus;

/// The default channel capacity for this module.
pub const CHANNEL_CAPACITY: usize = 1_000;

pub struct Node {
    pub commit: Receiver<Digest>,
}

impl Node {
    pub async fn new(
        committee_file: &str,
        key_file: &str,
        store_path: &str,
        parameters: Option<String>,
    ) -> Result<Self, ConfigError> {
        let (tx_commit, rx_commit) = channel(CHANNEL_CAPACITY);

        // Read the committee and secret key from file.
        let committee = Committee::read(committee_file)?;
        let secret = Secret::read(key_file)?;
        let name = secret.name;
        let secret_key = secret.secret;

        // Load default parameters if none are specified.
        let parameters = match parameters {
            Some(filename) => Parameters::read(&filename)?,
            None => Parameters::default(),
        };

        // Make the data store.
        let store = Store::new(store_path).expect("Failed to create store");

        // Run the signature service.
        let signature_service = SignatureService::new(secret_key);

        // Run the consensus core.
        Consensus::spawn(
            name,
            committee.consensus,
            parameters.consensus,
            signature_service,
            store.clone(),
            tx_commit,
        );

        info!("Node {} successfully booted", name);
        Ok(Self {commit: rx_commit })
    }

    pub fn print_key_file(filename: &str) -> Result<(), ConfigError> {
        Secret::new().write(filename)
    }

    pub async fn start(&mut self) {
        loop {
            tokio::select! {
                Some(blob) = self.commit.recv() => {
                    // Execute block
                    // TODO: execute the committed node's commands
                    info!("Executing committed block {:?}", blob);
                }
            }
        }
    }
}
