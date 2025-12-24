// Copyright(C) Facebook, Inc. and its affiliates.

// Standard library imports
use std::convert::TryInto;
use std::fmt;
use hex;

// External crate imports
use base64::{Engine as _, engine::general_purpose};
use rand::RngCore;
use serde::{de, ser, Deserialize, Serialize};
use tokio::sync::mpsc::{channel, Sender};
use tokio::sync::oneshot;
use zkp::{Scalar, Digest as ZkpDigest};

#[cfg(test)]
#[path = "tests/crypto_tests.rs"]
pub mod crypto_tests;

/// Represents a hash digest in hex string
#[derive(Hash, PartialEq, Default, Eq, Clone, Deserialize, Serialize, Ord, PartialOrd)]
pub struct Digest(pub String);

impl Digest {
    pub fn to_vec(&self) -> Vec<u8> {
        hex::decode(&self.0).expect("Digest string should be valid hex")
    }

    pub fn size(&self) -> usize {
        self.0.len()
    }

    pub fn to_field<S: Scalar, D: ZkpDigest<S>>(&self) -> D {
        D::from_hex(&self.0)
            .expect("Digest bytes is not valid for conversion to Digest in ZKP")
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}", &self.0)
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}", &self.0)
    }
}

/// This trait is implemented by all messages that can be hashed.
pub trait Hash {
    fn digest(&self) -> Digest;
}

/// Represents a public key (in bytes).
#[derive(Copy, Clone, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct PublicKey(pub [u8; 48]);

impl PublicKey {
    pub fn encode_base64(&self) -> String {
        general_purpose::STANDARD.encode(&self.0)
    }

    pub fn decode_base64(s: &str) -> Result<Self, base64::DecodeError> {
        const EXPECTED_LEN: usize = 48;
        let bytes = general_purpose::STANDARD.decode(s)?;
        
        if bytes.len() != EXPECTED_LEN {
            return Err(base64::DecodeError::InvalidLength);
        }
        
        let array = bytes.try_into().map_err(|_| base64::DecodeError::InvalidLength)?;
        Ok(Self(array))
    }
}

impl Default for PublicKey {
    fn default() -> Self {
        PublicKey([0u8; 48])
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}", self.encode_base64())
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}", self.encode_base64().get(0..16).unwrap())
    }
}

impl Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        serializer.serialize_str(&self.encode_base64())
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let value = Self::decode_base64(&s).map_err(|e| de::Error::custom(e.to_string()))?;
        Ok(value)
    }
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Represents a secret key (in bytes).
pub struct SecretKey([u8; 32]);

impl SecretKey {
    pub fn encode_base64(&self) -> String {
        general_purpose::STANDARD.encode(&self.0)
    }

    pub fn decode_base64(s: &str) -> Result<Self, base64::DecodeError> {
        const EXPECTED_LEN: usize = 32;
        let bytes = general_purpose::STANDARD.decode(s)?;
        
        if bytes.len() != EXPECTED_LEN {
            return Err(base64::DecodeError::InvalidLength);
        }
        
        let array = bytes.try_into().map_err(|_| base64::DecodeError::InvalidLength)?;
        Ok(Self(array))
    }
}

impl Serialize for SecretKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        serializer.serialize_str(&self.encode_base64())
    }
}

impl<'de> Deserialize<'de> for SecretKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let value = Self::decode_base64(&s).map_err(|e| de::Error::custom(e.to_string()))?;
        Ok(value)
    }
}

#[derive(Clone, Debug)]
pub struct Signature(pub [u8; 96]);

impl Signature {
    pub fn encode_base64(&self) -> String {
        general_purpose::STANDARD.encode(&self.0[..])
    }

    pub fn decode_base64(s: &str) -> Result<Self, base64::DecodeError> {
        const EXPECTED_LEN: usize = 96;
        let bytes = general_purpose::STANDARD.decode(s)?;
        
        if bytes.len() != EXPECTED_LEN {
            return Err(base64::DecodeError::InvalidLength);
        }
        
        let array = bytes.try_into().map_err(|_| base64::DecodeError::InvalidLength)?;
        Ok(Self(array))
    }
}

impl Serialize for Signature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        serializer.serialize_str(&self.encode_base64())
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let value = Self::decode_base64(&s).map_err(|e| de::Error::custom(e.to_string()))?;
        Ok(value)
    }
}

impl Default for Signature {
    fn default() -> Self {
        Signature([0u8; 96])
    }
}

/// Generates a new production-ready keypair using cryptographically secure random generation
pub fn generate_production_keypair() -> (PublicKey, SecretKey) {
    const IKM_LEN: usize = 32;
    
    let mut rng = rand::thread_rng();
    let mut ikm = [0u8; IKM_LEN];
    rng.fill_bytes(&mut ikm);
    
    let sk = blst::min_pk::SecretKey::key_gen(&ikm, &[])
        .expect("Key generation should always succeed with valid IKM");
    
    let pk = sk.sk_to_pk();
    (PublicKey(pk.to_bytes()), SecretKey(sk.to_bytes()))
}

/// This service holds the node's private key. It takes digests as input and returns a signature
/// over the digest (through a oneshot channel).
#[derive(Clone)]
pub struct SignatureService {
    channel: Sender<(Digest, oneshot::Sender<Signature>)>,
}

impl SignatureService {
    pub fn new(secret: SecretKey) -> Self {
        const CHANNEL_BUFFER: usize = 100;
        const BLS_DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
        
        let (tx, mut rx): (Sender<(Digest, oneshot::Sender<Signature>)>, _) = channel(CHANNEL_BUFFER);
        
        tokio::spawn(async move {
            let sk = blst::min_pk::SecretKey::from_bytes(&secret.0)
                .expect("SecretKey bytes should be valid for BLS key construction");
                
            while let Some((digest, sender)) = rx.recv().await {
                let signature = sk.sign(&digest.to_vec(), BLS_DST, &[]);
                // Ignore send error as receiver might have dropped
                let _ = sender.send(Signature(signature.to_bytes()));
            }
        });
        
        Self { channel: tx }
    }

    pub async fn request_signature(&mut self, digest: Digest) -> Signature {
        let (sender, receiver) = oneshot::channel();
        
        self.channel
            .send((digest, sender))
            .await
            .expect("SignatureService should be running");
            
        receiver
            .await
            .expect("Signature should be generated successfully")
    }
}
