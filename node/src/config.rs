// Standard library imports
use std::fs::{self, OpenOptions};
use std::io::{BufWriter, Write as _};

// External crate imports
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use thiserror::Error;

// Internal crate imports
use consensus::{Committee as ConsensusCommittee, Parameters as ConsensusParameters};
use crypto::{generate_production_keypair, PublicKey, SecretKey};

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("Failed to read config file '{file}': {message}")]
    ReadError { file: String, message: String },

    #[error("Failed to write config file '{file}': {message}")]
    WriteError { file: String, message: String },
}

pub trait Export: Serialize + DeserializeOwned {
    fn read(path: &str) -> Result<Self, ConfigError> {
        let data = fs::read(path).map_err(|e| ConfigError::ReadError {
            file: path.to_string(),
            message: e.to_string(),
        })?;
        
        serde_json::from_slice(&data).map_err(|e| ConfigError::ReadError {
            file: path.to_string(),
            message: format!("JSON parsing error: {}", e),
        })
    }

    fn write(&self, path: &str) -> Result<(), ConfigError> {
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(path)
            .map_err(|e| ConfigError::WriteError {
                file: path.to_string(),
                message: e.to_string(),
            })?;
            
        let mut writer = BufWriter::new(file);
        let data = serde_json::to_string_pretty(self)
            .map_err(|e| ConfigError::WriteError {
                file: path.to_string(),
                message: format!("JSON serialization error: {}", e),
            })?;
            
        writer.write_all(data.as_bytes()).map_err(|e| ConfigError::WriteError {
            file: path.to_string(),
            message: e.to_string(),
        })?;
        
        writer.write_all(b"\n").map_err(|e| ConfigError::WriteError {
            file: path.to_string(),
            message: e.to_string(),
        })?;
        
        Ok(())
    }
}

#[derive(Serialize, Deserialize, Default)]
pub struct Parameters {
    pub consensus: ConsensusParameters,
}

impl Export for Parameters {}

#[derive(Serialize, Deserialize)]
pub struct Secret {
    pub name: PublicKey,
    pub secret: SecretKey,
}

impl Secret {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Export for Secret {}

impl Default for Secret {
    fn default() -> Self {
        let (name, secret) = generate_production_keypair();
        Self { name, secret }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Committee {
    pub consensus: ConsensusCommittee,
}

impl Export for Committee {}
