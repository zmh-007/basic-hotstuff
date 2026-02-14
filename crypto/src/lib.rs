// Standard library imports
use std::convert::TryInto;
use std::fmt;
use std::marker::PhantomData;

// External crate imports
use hex::FromHex;
use base64::{Engine as _, engine::general_purpose};
use anyhow::Result;
use rand::RngCore;
use serde::{de, ser, Deserialize, Serialize};
use tokio::sync::mpsc::{channel, Sender};
use tokio::sync::oneshot;
use zkp::{Scalar, Digest as ZkpDigest, AsScalars};
use generic_array::GenericArray;
use generic_array::typenum::Unsigned;

#[cfg(test)]
#[path = "tests/crypto_tests.rs"]
pub mod crypto_tests;

/// Represents a hash digest in hex string
#[derive(Hash, PartialEq, Eq, Clone, Deserialize, Serialize, Ord, PartialOrd)]
pub struct Digest<S: Scalar, D: ZkpDigest<S>> {
    pub value: String,
    #[serde(skip)]
    pub _phantom: PhantomData<(S, D)>,
}

impl<S: Scalar, D: ZkpDigest<S>> Default for Digest<S, D> {
    fn default() -> Self {
        Digest {
            value: String::new(),
            _phantom: PhantomData,
        }
    }
}

impl<S: Scalar, D: ZkpDigest<S>> Digest<S, D> {
    pub fn to_vec(&self) -> Vec<u8> {
        hex::decode(&self.value).expect("Digest string should be valid hex")
    }

    pub fn to_field(&self) -> D {
        if self.value.is_empty() {
            return D::default();
        }
        digest_from_hex(&self.value).expect("Digest bytes is not valid for conversion to Digest in ZKP")
    }
}

impl<S: Scalar, D: ZkpDigest<S>> fmt::Debug for Digest<S, D> {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}", &self.value)
    }
}

impl<S: Scalar, D: ZkpDigest<S>> fmt::Display for Digest<S, D> {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}", &self.value)
    }
}

pub fn digest_from_hex<S: Scalar, D: ZkpDigest<S> + AsScalars, T: AsRef<[u8]>>(hex: T) -> Result<D> {
    let scalar_hex_len = S::BYTELEN::to_usize() * 2;
    let vecs = hex.as_ref().chunks(scalar_hex_len).map(|v| {
        Ok(S::from_bytes(GenericArray::try_from_iter(Vec::from_hex(v)?)?))
    }).collect::<Result<Vec<S>>>()?;
    Ok(D::from_scalars(GenericArray::try_from_iter(vecs)?))
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
pub struct SignatureService<S: Scalar + 'static, D: ZkpDigest<S> + 'static> {
    channel: Sender<(Digest<S, D>, oneshot::Sender<Signature>)>,
}

impl<S: Scalar + 'static, D: ZkpDigest<S> + 'static> SignatureService<S, D> {
    pub fn new(secret: SecretKey) -> Self {
        const CHANNEL_BUFFER: usize = 100;
        const BLS_DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
        
        let (tx, mut rx): (Sender<(Digest<S, D>, oneshot::Sender<Signature>)>, _) = channel(CHANNEL_BUFFER);
        
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

    pub async fn request_signature(&mut self, digest: Digest<S, D>) -> Signature {
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
