use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::{
    error::CryptoError,
    handshake::{
        self, HandshakeFinish, HandshakeInit, HandshakeInitiator, HandshakeResponder,
        HandshakeResponse,
    },
    identity::{IdentityKeypair, IdentityPublicKey},
    ratchet::{DoubleRatchetState, RatchetMessage},
    replay_store::HandshakeReplayStore,
    serialization, SecretBytes,
};

/// The application-facing identity. The Ed25519 signing key and its
/// domain-separated Noise static-key derivation remain local and are never
/// serialized or exposed through this API. Protect the exported seed before
/// persistence; it reproduces both identity keys.
pub struct Identity {
    keypair: IdentityKeypair,
}

impl Identity {
    /// Creates a new Ed25519 identity using the operating system CSPRNG.
    pub fn generate() -> Result<Self, CryptoError> {
        Ok(Self {
            keypair: IdentityKeypair::generate()?,
        })
    }

    /// Imports a 32-byte Ed25519 signing seed. The separate Noise static key is
    /// derived from this seed with a domain-separated HKDF label. The caller
    /// should zeroize its input buffer and load the seed from protected storage.
    pub fn from_secret_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let mut seed: [u8; 32] = bytes
            .try_into()
            .map_err(|_| CryptoError::InvalidKeyLength { expected: 32 })?;
        let keypair = IdentityKeypair::from_bytes(seed);
        seed.zeroize();
        Ok(Self { keypair })
    }

    /// Exports the local Ed25519 signing seed in a zeroizing container. This
    /// seed also reproduces the domain-separated Noise static private key.
    ///
    /// This is raw secret material; callers must protect it before persistence
    /// and must never transmit or log it.
    pub fn export_secret_bytes(&self) -> SecretBytes {
        self.keypair.export_secret_bytes()
    }

    /// Returns the public identity key suitable for peer pinning and exchange.
    pub fn public_key(&self) -> IdentityPublicKey {
        self.keypair.public_key()
    }

    /// Starts an authenticated 1:1 handshake and returns its public first flight.
    pub fn initiate_handshake(
        &self,
        expected_peer: IdentityPublicKey,
    ) -> Result<(InitiatorHandshake, Handshake), CryptoError> {
        let (inner, init) = HandshakeInitiator::start(&self.keypair, expected_peer)?;
        Ok((InitiatorHandshake { inner }, Handshake::Init(init)))
    }

    /// Validates a peer-pinned initiator flight and atomically records its
    /// replay identifier before returning responder state. Use a durable
    /// store if first-flight replay protection must survive process restarts.
    pub fn respond_to_handshake(
        &self,
        expected_peer: IdentityPublicKey,
        init: Handshake,
        replay_store: &dyn HandshakeReplayStore,
    ) -> Result<(ResponderHandshake, Handshake), CryptoError> {
        let Handshake::Init(init) = init else {
            return Err(CryptoError::InvalidHandshakeState);
        };
        let (inner, response) =
            HandshakeResponder::respond(&self.keypair, expected_peer, &init, replay_store)?;
        Ok((ResponderHandshake { inner }, Handshake::Response(response)))
    }
}

impl core::fmt::Debug for Identity {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("Identity([REDACTED])")
    }
}

/// A serialized public handshake flight. It contains no private key material.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum Handshake {
    Init(HandshakeInit),
    Response(HandshakeResponse),
    Finish(HandshakeFinish),
}

impl Handshake {
    pub fn to_bytes(&self) -> Result<Vec<u8>, CryptoError> {
        match self {
            Self::Init(message) => {
                handshake::serialize_init(message)?;
            }
            Self::Response(message) => {
                handshake::serialize_response(message)?;
            }
            Self::Finish(message) => {
                handshake::serialize_finish(message)?;
            }
        }
        let encoded = serialization::serialize(self).map_err(|_| CryptoError::MalformedMessage)?;
        if encoded.len() > 4096 {
            return Err(CryptoError::MessageTooLarge);
        }
        Ok(encoded)
    }

    pub fn from_bytes(encoded: &[u8]) -> Result<Self, CryptoError> {
        if encoded.len() > 4096 {
            return Err(CryptoError::MessageTooLarge);
        }
        let message: Self =
            serialization::deserialize(encoded).map_err(|_| CryptoError::MalformedMessage)?;
        message.to_bytes()?;
        Ok(message)
    }
}

/// Initiator's one-use pending handshake. Processing the response consumes it.
pub struct InitiatorHandshake {
    inner: HandshakeInitiator,
}

impl InitiatorHandshake {
    /// Authenticates the pinned responder and completes the initiator flight.
    pub fn process_response(
        self,
        identity: &Identity,
        response: Handshake,
    ) -> Result<(Handshake, Session), CryptoError> {
        let Handshake::Response(response) = response else {
            return Err(CryptoError::InvalidHandshakeState);
        };
        let (finish, state) = self.inner.process_response(&identity.keypair, &response)?;
        Ok((Handshake::Finish(finish), Session { state }))
    }
}

/// Responder's one-use pending Noise handshake. A session is returned only
/// after validating the initiator's final identity binding and Noise message.
pub struct ResponderHandshake {
    inner: HandshakeResponder,
}

impl ResponderHandshake {
    pub fn complete(self, finish: Handshake) -> Result<Session, CryptoError> {
        let Handshake::Finish(finish) = finish else {
            return Err(CryptoError::InvalidHandshakeState);
        };
        Ok(Session {
            state: self.inner.process_finish(&finish)?,
        })
    }
}

/// Application-facing 1:1 encrypted-message payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Message {
    inner: RatchetMessage,
}

impl Message {
    /// Encodes the public versioned message header and ciphertext with Postcard.
    pub fn to_bytes(&self) -> Result<Vec<u8>, CryptoError> {
        DoubleRatchetState::serialize_message(&self.inner)
    }

    /// Parses and validates a bounded public protocol message.
    pub fn from_bytes(encoded: &[u8]) -> Result<Self, CryptoError> {
        Ok(Self {
            inner: DoubleRatchetState::deserialize_message(encoded)?,
        })
    }
}

/// Application-facing ratchet session.
///
/// This object holds secret root, chain, DH, and skipped-message key material.
/// Keep it local. Persistence requires a separately protected 32-byte storage
/// key; exported snapshots are authenticated ciphertext and do not contain it.
pub struct Session {
    state: DoubleRatchetState,
}

impl Session {
    /// Encrypts plaintext; returned messages contain only public header and ciphertext.
    pub fn encrypt(
        &mut self,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<Message, CryptoError> {
        Ok(Message {
            inner: self.state.encrypt(plaintext, associated_data)?,
        })
    }

    /// Authenticates and decrypts a message. Plaintext is returned in a
    /// zeroizing container and the session advances only on success.
    pub fn decrypt(
        &mut self,
        message: &Message,
        associated_data: &[u8],
    ) -> Result<SecretBytes, CryptoError> {
        self.state.decrypt(&message.inner, associated_data)
    }

    /// Sets the maximum number of retained out-of-order keys (at most 20,000).
    pub fn set_max_skipped_message_keys(&mut self, limit: usize) -> Result<(), CryptoError> {
        self.state.set_max_skipped_message_keys(limit)
    }

    pub fn skipped_message_key_count(&self) -> usize {
        self.state.skipped_message_key_count()
    }

    /// Exports an authenticated-encrypted snapshot using a caller-provided
    /// 32-byte storage key. The returned bytes contain ciphertext, not raw
    /// session state; the caller remains responsible for protecting the key.
    pub fn export_state(&self, storage_key: &[u8; 32]) -> Result<Vec<u8>, CryptoError> {
        self.state.export_state(storage_key)
    }

    /// Authenticates and decrypts a snapshot with the same caller-provided
    /// 32-byte storage key used for export, then validates its state format.
    pub fn import_state(encoded: &[u8], storage_key: &[u8; 32]) -> Result<Self, CryptoError> {
        Ok(Self {
            state: DoubleRatchetState::import_state(encoded, storage_key)?,
        })
    }
}

impl core::fmt::Debug for Session {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("Session")
            .field("state", &self.state)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::{Handshake, Identity, Message, Session};
    use crate::{IdentityPublicKey, VolatileHandshakeReplayStore};

    #[test]
    fn facade_supports_authenticated_handshake_and_messages() {
        let alice = Identity::from_secret_bytes(&[51; 32]).expect("valid seed");
        let bob = Identity::from_secret_bytes(&[52; 32]).expect("valid seed");
        let replay_store = VolatileHandshakeReplayStore::default();
        let (alice_pending, init) = alice
            .initiate_handshake(bob.public_key())
            .expect("start handshake");
        let init_wire = init.to_bytes().expect("encode initial flight");
        let init = Handshake::from_bytes(&init_wire).expect("decode initial flight");
        let (bob_pending, response) = bob
            .respond_to_handshake(alice.public_key(), init, &replay_store)
            .expect("respond to pinned identity");
        let response = Handshake::from_bytes(&response.to_bytes().expect("encode response"))
            .expect("decode response");
        let (finish, mut alice_session) = alice_pending
            .process_response(&alice, response)
            .expect("process authenticated response");
        let finish = Handshake::from_bytes(&finish.to_bytes().expect("encode finish"))
            .expect("decode finish");
        let mut bob_session = bob_pending.complete(finish).expect("complete handshake");

        let message = alice_session
            .encrypt(b"hello", b"conversation")
            .expect("encrypt");
        let message = Message::from_bytes(&message.to_bytes().expect("encode message"))
            .expect("decode message");
        assert_eq!(
            bob_session
                .decrypt(&message, b"conversation")
                .expect("decrypt")
                .as_slice(),
            b"hello"
        );
        let reply = bob_session.encrypt(b"hi", b"conversation").expect("reply");
        assert_eq!(
            alice_session
                .decrypt(&reply, b"conversation")
                .expect("decrypt reply")
                .as_slice(),
            b"hi"
        );

        let storage_key = [0x83; 32];
        let state = alice_session
            .export_state(&storage_key)
            .expect("export session state");
        let mut restored =
            Session::import_state(&state, &storage_key).expect("restore session state");
        let message = restored
            .encrypt(b"resumed", b"conversation")
            .expect("encrypt after restore");
        assert_eq!(
            bob_session
                .decrypt(&message, b"conversation")
                .expect("decrypt resumed message")
                .as_slice(),
            b"resumed"
        );
    }

    #[test]
    fn facade_rejects_handshake_flights_in_the_wrong_order() {
        let identity = Identity::from_secret_bytes(&[61; 32]).expect("valid seed");
        let replay_store = VolatileHandshakeReplayStore::default();
        let wrong_flight = Handshake::Finish(crate::handshake::HandshakeFinish {
            version: 2,
            noise_message: vec![],
        });

        assert!(matches!(
            identity.respond_to_handshake(
                IdentityPublicKey::from_bytes([62; 32]),
                wrong_flight,
                &replay_store
            ),
            Err(crate::CryptoError::InvalidHandshakeState)
        ));
    }

    #[test]
    fn identity_secret_export_import_preserves_public_identity() {
        let original = Identity::from_secret_bytes(&[66; 32]).expect("valid identity seed");
        let exported = original.export_secret_bytes();
        let restored = Identity::from_secret_bytes(exported.as_slice()).expect("restore identity");

        assert_eq!(original.public_key(), restored.public_key());
        assert!(matches!(
            Identity::from_secret_bytes(&[1, 2, 3]),
            Err(crate::CryptoError::InvalidKeyLength { expected: 32 })
        ));
    }

    #[test]
    fn facade_rejects_malformed_handshake_serialization() {
        assert!(matches!(
            Handshake::from_bytes(&[0xff, 0xff]),
            Err(crate::CryptoError::MalformedMessage)
        ));
    }
}
