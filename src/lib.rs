#![doc = include_str!("../README.md")]

mod aead;
mod error;
mod facade;
mod handshake;
mod identity;
mod kdf;
mod noise_split;
mod random;
mod ratchet;
mod replay_store;
mod serialization;

pub use error::CryptoError;
pub use facade::{Handshake, Identity, InitiatorHandshake, Message, ResponderHandshake, Session};
pub use handshake::{HandshakeFinish, HandshakeInit, HandshakeResponse};
pub use identity::{IdentityPublicKey, PublicKey as DhPublicKey};
pub use replay_store::{
    HandshakeReplayId, HandshakeReplayStore, ReplayDecision, VolatileHandshakeReplayStore,
};

use zeroize::{Zeroize, ZeroizeOnDrop};

/// Secret bytes that are zeroized when dropped.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    pub(crate) fn from_array<const N: usize>(mut bytes: [u8; N]) -> Self {
        let secret = Self(bytes.to_vec());
        bytes.zeroize();
        secret
    }

    pub(crate) fn from_vec(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub(crate) fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.0
    }

    pub(crate) fn duplicate(&self) -> Self {
        Self(self.0.clone())
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl core::fmt::Debug for SecretBytes {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("SecretBytes([REDACTED])")
    }
}
