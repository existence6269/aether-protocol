use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey as DalekPublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{error::CryptoError, kdf::derive_key, random::random_array, SecretBytes};

const NOISE_STATIC_KEY_LABEL: &[u8] = b"aether/noise/xx/static-x25519/v1";

/// An X25519 public key.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct PublicKey([u8; 32]);

impl PublicKey {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// An Ed25519 verification key used as the long-term identity.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct IdentityPublicKey([u8; 32]);

impl IdentityPublicKey {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub(crate) fn verifying_key(&self) -> Result<VerifyingKey, CryptoError> {
        VerifyingKey::from_bytes(&self.0).map_err(|_| CryptoError::InvalidIdentityKey)
    }
}

/// An Ed25519 identity signing key; its secret bytes never leave this wrapper.
pub struct IdentityKeypair {
    signing_key: SigningKey,
    public_key: VerifyingKey,
}

impl IdentityKeypair {
    pub fn generate() -> Result<Self, CryptoError> {
        let bytes = random_array()?;
        Ok(Self::from_bytes(bytes))
    }

    pub fn from_bytes(mut bytes: [u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(&bytes);
        let public_key = signing_key.verifying_key();
        bytes.zeroize();
        Self {
            signing_key,
            public_key,
        }
    }

    pub fn public_key(&self) -> IdentityPublicKey {
        IdentityPublicKey(self.public_key.to_bytes())
    }

    pub(crate) fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.signing_key.sign(message).to_bytes()
    }

    pub(crate) fn export_secret_bytes(&self) -> crate::SecretBytes {
        crate::SecretBytes::from_array(self.signing_key.to_bytes())
    }

    pub(crate) fn noise_static_secret(&self) -> Result<SecretKey, CryptoError> {
        let identity = self.public_key();
        let seed = self.export_secret_bytes();
        let mut derived = derive_key(
            Some(identity.as_bytes()),
            seed.as_slice(),
            NOISE_STATIC_KEY_LABEL,
            32,
        )?;
        let mut secret_bytes = [0u8; 32];
        secret_bytes.copy_from_slice(derived.as_slice());
        derived.as_mut_slice().zeroize();
        Ok(SecretKey::from_bytes(secret_bytes))
    }

    pub(crate) fn noise_static_public(&self) -> Result<PublicKey, CryptoError> {
        Ok(self.noise_static_secret()?.public_key())
    }
}

impl core::fmt::Debug for IdentityKeypair {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("IdentityKeypair([REDACTED])")
    }
}

pub(crate) fn verify_signature(
    public_key: &IdentityPublicKey,
    message: &[u8],
    signature: &[u8],
) -> Result<(), CryptoError> {
    let verifying_key = public_key.verifying_key()?;
    let signature: &[u8; 64] = signature
        .try_into()
        .map_err(|_| CryptoError::InvalidSignature)?;
    let signature = ed25519_dalek::Signature::from_bytes(signature);
    verifying_key
        .verify_strict(message, &signature)
        .map_err(|_| CryptoError::InvalidSignature)
}

/// An X25519 private key that is zeroized when dropped.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretKey {
    bytes: [u8; 32],
}

impl SecretKey {
    pub fn generate() -> Result<Self, CryptoError> {
        Ok(Self {
            bytes: random_array()?,
        })
    }

    pub fn from_bytes(mut bytes: [u8; 32]) -> Self {
        let secret = Self { bytes };
        bytes.zeroize();
        secret
    }

    pub(crate) fn export_bytes(&self) -> [u8; 32] {
        self.bytes
    }

    pub(crate) fn duplicate(&self) -> Self {
        Self { bytes: self.bytes }
    }

    pub fn public_key(&self) -> PublicKey {
        let secret = StaticSecret::from(self.bytes);
        PublicKey(DalekPublicKey::from(&secret).to_bytes())
    }

    pub fn diffie_hellman(&self, peer_public_key: &PublicKey) -> Result<SecretBytes, CryptoError> {
        let secret = StaticSecret::from(self.bytes);
        let peer = DalekPublicKey::from(*peer_public_key.as_bytes());
        let shared_secret = secret.diffie_hellman(&peer);

        if !shared_secret.was_contributory() {
            return Err(CryptoError::NonContributoryPublicKey);
        }

        Ok(SecretBytes::from_array(shared_secret.to_bytes()))
    }
}

impl core::fmt::Debug for SecretKey {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("SecretKey([REDACTED])")
    }
}

#[cfg(test)]
mod tests {
    use super::{PublicKey, SecretKey};
    use crate::CryptoError;

    #[test]
    fn generated_keys_produce_matching_shared_secrets() {
        let alice = SecretKey::generate().expect("secure randomness should be available");
        let bob = SecretKey::generate().expect("secure randomness should be available");

        let alice_shared = alice
            .diffie_hellman(&bob.public_key())
            .expect("valid peer key should contribute");
        let bob_shared = bob
            .diffie_hellman(&alice.public_key())
            .expect("valid peer key should contribute");

        assert_eq!(alice_shared.as_slice(), bob_shared.as_slice());
    }

    #[test]
    fn rejects_non_contributory_public_keys() {
        let secret = SecretKey::generate().expect("secure randomness should be available");
        let low_order_public_key = PublicKey::from_bytes([0; 32]);

        assert!(matches!(
            secret.diffie_hellman(&low_order_public_key),
            Err(CryptoError::NonContributoryPublicKey)
        ));
    }

    #[test]
    fn identity_private_debug_is_redacted() {
        let identity = super::IdentityKeypair::from_bytes([9; 32]);
        let debug = format!("{identity:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("090909"));
    }

    #[test]
    fn noise_static_key_is_separate_and_reproducible_from_identity_seed() {
        let identity = super::IdentityKeypair::from_bytes([17; 32]);
        let first = identity
            .noise_static_secret()
            .expect("derive separate Noise static key");
        let second = identity
            .noise_static_secret()
            .expect("derive reproducible Noise static key");

        assert_eq!(first.export_bytes(), second.export_bytes());
        assert_ne!(first.export_bytes(), [17; 32]);
        assert_eq!(
            first.public_key(),
            identity
                .noise_static_public()
                .expect("derive Noise static public key")
        );
        assert!(format!("{first:?}").contains("[REDACTED]"));
    }
}
