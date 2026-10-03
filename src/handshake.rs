use serde::{
    de::{Error as DeError, SeqAccess, Visitor},
    Deserialize, Deserializer, Serialize,
};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{
    error::CryptoError,
    identity::{verify_signature, IdentityKeypair, IdentityPublicKey, PublicKey, SecretKey},
    noise_split::derive_ratchet_root,
    ratchet::DoubleRatchetState,
    replay_store::{HandshakeReplayId, HandshakeReplayStore, ReplayDecision},
    serialization,
};

const VERSION: u8 = 2;
const NOISE_PROTOCOL: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";
const PROFILE_LABEL: &[u8] = b"aether/noise-xx/double-ratchet/v2";
const REPLAY_LABEL: &[u8] = b"aether/noise-xx/flight-1-replay/v1";
const RESPONDER_SIGNATURE_LABEL: &[u8] = b"aether/noise-xx/signature/responder/v2";
const INITIATOR_SIGNATURE_LABEL: &[u8] = b"aether/noise-xx/signature/initiator/v2";
const MAX_HANDSHAKE_MESSAGE_BYTES: usize = 4096;
const MAX_NOISE_PAYLOAD_BYTES: usize = 1024;
const NOISE_HASH_LENGTH: usize = 32;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HandshakeInit {
    pub version: u8,
    pub noise_message: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HandshakeResponse {
    pub version: u8,
    pub noise_message: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HandshakeFinish {
    pub version: u8,
    pub noise_message: Vec<u8>,
}

#[derive(Serialize)]
struct NoisePrologue {
    label: &'static [u8],
    version: u8,
    initiator_identity: IdentityPublicKey,
    responder_identity: IdentityPublicKey,
}

#[derive(Clone, Deserialize, Serialize)]
struct ResponderPayload {
    identity: IdentityPublicKey,
    ratchet_public_key: PublicKey,
    #[serde(deserialize_with = "deserialize_signature")]
    signature: Vec<u8>,
}

#[derive(Clone, Deserialize, Serialize)]
struct InitiatorPayload {
    identity: IdentityPublicKey,
    ratchet_public_key: PublicKey,
    #[serde(deserialize_with = "deserialize_signature")]
    signature: Vec<u8>,
}

fn deserialize_signature<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
    struct SignatureVisitor;

    impl<'de> Visitor<'de> for SignatureVisitor {
        type Value = Vec<u8>;

        fn expecting(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            formatter.write_str("an Ed25519 signature of exactly 64 bytes")
        }

        fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
            let mut signature = Vec::with_capacity(64);
            while let Some(byte) = sequence.next_element()? {
                if signature.len() == 64 {
                    return Err(A::Error::custom("signature exceeds 64 bytes"));
                }
                signature.push(byte);
            }
            if signature.len() != 64 {
                return Err(A::Error::custom("signature must be 64 bytes"));
            }
            Ok(signature)
        }
    }

    deserializer.deserialize_seq(SignatureVisitor)
}

#[derive(Serialize)]
struct ResponderSignatureInput {
    label: &'static [u8],
    version: u8,
    prior_handshake_hash: [u8; NOISE_HASH_LENGTH],
    initiator_identity: IdentityPublicKey,
    responder_identity: IdentityPublicKey,
    responder_noise_static: PublicKey,
    responder_ratchet_public: PublicKey,
}

#[derive(Serialize)]
struct InitiatorSignatureInput {
    label: &'static [u8],
    version: u8,
    prior_handshake_hash: [u8; NOISE_HASH_LENGTH],
    initiator_identity: IdentityPublicKey,
    responder_identity: IdentityPublicKey,
    initiator_noise_static: PublicKey,
    responder_noise_static: PublicKey,
    initiator_ratchet_public: PublicKey,
}

pub fn serialize_init(message: &HandshakeInit) -> Result<Vec<u8>, CryptoError> {
    validate_version(message.version)?;
    serialize_handshake(message)
}

pub fn serialize_response(message: &HandshakeResponse) -> Result<Vec<u8>, CryptoError> {
    validate_version(message.version)?;
    serialize_handshake(message)
}

pub fn serialize_finish(message: &HandshakeFinish) -> Result<Vec<u8>, CryptoError> {
    validate_version(message.version)?;
    serialize_handshake(message)
}

fn serialize_handshake<T: Serialize>(message: &T) -> Result<Vec<u8>, CryptoError> {
    let encoded = serialization::serialize(message).map_err(|_| CryptoError::MalformedMessage)?;
    if encoded.len() > MAX_HANDSHAKE_MESSAGE_BYTES {
        return Err(CryptoError::MessageTooLarge);
    }
    Ok(encoded)
}

fn validate_version(version: u8) -> Result<(), CryptoError> {
    if version == VERSION {
        Ok(())
    } else {
        Err(CryptoError::InvalidProtocolVersion { received: version })
    }
}

fn map_noise_error(error: snow::Error) -> CryptoError {
    match error {
        snow::Error::Decrypt => CryptoError::AuthenticationFailed,
        snow::Error::Input => CryptoError::MalformedMessage,
        snow::Error::Dh => CryptoError::NonContributoryPublicKey,
        snow::Error::Rng => CryptoError::RandomGenerationFailed,
        snow::Error::State(_) => CryptoError::InvalidHandshakeState,
        _ => CryptoError::NoiseHandshakeFailed,
    }
}

fn encode_prologue(
    initiator_identity: IdentityPublicKey,
    responder_identity: IdentityPublicKey,
) -> Result<Vec<u8>, CryptoError> {
    serialization::serialize(&NoisePrologue {
        label: PROFILE_LABEL,
        version: VERSION,
        initiator_identity,
        responder_identity,
    })
    .map_err(|_| CryptoError::MalformedMessage)
}

fn build_noise_state(
    identity: &IdentityKeypair,
    initiator_identity: IdentityPublicKey,
    responder_identity: IdentityPublicKey,
    initiator: bool,
) -> Result<snow::HandshakeState, CryptoError> {
    let prologue = encode_prologue(initiator_identity, responder_identity)?;
    let params = NOISE_PROTOCOL
        .parse::<snow::params::NoiseParams>()
        .map_err(map_noise_error)?;
    let static_secret = identity.noise_static_secret()?;
    let static_bytes = Zeroizing::new(static_secret.export_bytes());
    let builder = snow::Builder::new(params)
        .prologue(&prologue)
        .map_err(map_noise_error)?
        .local_private_key(&static_bytes[..])
        .map_err(map_noise_error)?;

    if initiator {
        builder.build_initiator().map_err(map_noise_error)
    } else {
        builder.build_responder().map_err(map_noise_error)
    }
}

fn noise_hash(state: &snow::HandshakeState) -> Result<[u8; NOISE_HASH_LENGTH], CryptoError> {
    let hash = state.get_handshake_hash();
    if hash.len() != NOISE_HASH_LENGTH {
        return Err(CryptoError::NoiseHandshakeFailed);
    }
    let mut result = [0u8; NOISE_HASH_LENGTH];
    result.copy_from_slice(hash);
    Ok(result)
}

fn write_noise_message(
    state: &mut snow::HandshakeState,
    payload: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let mut message = vec![0u8; MAX_HANDSHAKE_MESSAGE_BYTES];
    let length = state
        .write_message(payload, &mut message)
        .map_err(map_noise_error)?;
    message.truncate(length);
    Ok(message)
}

fn read_noise_message(
    state: &mut snow::HandshakeState,
    message: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if message.len() > MAX_HANDSHAKE_MESSAGE_BYTES {
        return Err(CryptoError::MessageTooLarge);
    }
    let mut payload = [0u8; MAX_NOISE_PAYLOAD_BYTES];
    let length = state
        .read_message(message, &mut payload)
        .map_err(map_noise_error)?;
    Ok(payload[..length].to_vec())
}

fn replay_id(responder_identity: IdentityPublicKey, init: &HandshakeInit) -> HandshakeReplayId {
    let mut hash = Sha256::new();
    hash.update(REPLAY_LABEL);
    hash.update([init.version]);
    hash.update(responder_identity.as_bytes());
    hash.update((init.noise_message.len() as u32).to_be_bytes());
    hash.update(&init.noise_message);
    HandshakeReplayId::from_digest(hash.finalize().into())
}

fn responder_signature_input(
    prior_handshake_hash: [u8; NOISE_HASH_LENGTH],
    initiator_identity: IdentityPublicKey,
    responder_identity: IdentityPublicKey,
    responder_noise_static: PublicKey,
    responder_ratchet_public: PublicKey,
) -> Result<Vec<u8>, CryptoError> {
    serialization::serialize(&ResponderSignatureInput {
        label: RESPONDER_SIGNATURE_LABEL,
        version: VERSION,
        prior_handshake_hash,
        initiator_identity,
        responder_identity,
        responder_noise_static,
        responder_ratchet_public,
    })
    .map_err(|_| CryptoError::MalformedMessage)
}

fn initiator_signature_input(
    prior_handshake_hash: [u8; NOISE_HASH_LENGTH],
    initiator_identity: IdentityPublicKey,
    responder_identity: IdentityPublicKey,
    initiator_noise_static: PublicKey,
    responder_noise_static: PublicKey,
    initiator_ratchet_public: PublicKey,
) -> Result<Vec<u8>, CryptoError> {
    serialization::serialize(&InitiatorSignatureInput {
        label: INITIATOR_SIGNATURE_LABEL,
        version: VERSION,
        prior_handshake_hash,
        initiator_identity,
        responder_identity,
        initiator_noise_static,
        responder_noise_static,
        initiator_ratchet_public,
    })
    .map_err(|_| CryptoError::MalformedMessage)
}

fn remote_noise_static(state: &snow::HandshakeState) -> Result<PublicKey, CryptoError> {
    let bytes: [u8; 32] = state
        .get_remote_static()
        .ok_or(CryptoError::InvalidHandshakeState)?
        .try_into()
        .map_err(|_| CryptoError::MalformedMessage)?;
    Ok(PublicKey::from_bytes(bytes))
}

fn validate_noise_ephemeral(identity: &IdentityKeypair, message: &[u8]) -> Result<(), CryptoError> {
    let bytes: [u8; 32] = message
        .get(..32)
        .ok_or(CryptoError::MalformedMessage)?
        .try_into()
        .map_err(|_| CryptoError::MalformedMessage)?;
    identity
        .noise_static_secret()?
        .diffie_hellman(&PublicKey::from_bytes(bytes))?;
    Ok(())
}

/// Initiator's pending Noise XX handshake. It is single-use.
pub struct HandshakeInitiator {
    expected_responder: IdentityPublicKey,
    initiator_identity: IdentityPublicKey,
    initiator_noise_static: PublicKey,
    initiator_ratchet_secret: SecretKey,
    prior_handshake_hash: [u8; NOISE_HASH_LENGTH],
    noise: snow::HandshakeState,
}

impl HandshakeInitiator {
    pub fn start(
        identity: &IdentityKeypair,
        expected_responder: IdentityPublicKey,
    ) -> Result<(Self, HandshakeInit), CryptoError> {
        let initiator_identity = identity.public_key();
        let initiator_noise_static = identity.noise_static_public()?;
        let initiator_ratchet_secret = SecretKey::generate()?;
        let mut noise = build_noise_state(identity, initiator_identity, expected_responder, true)?;
        let noise_message = write_noise_message(&mut noise, &[])?;
        let prior_handshake_hash = noise_hash(&noise)?;
        let init = HandshakeInit {
            version: VERSION,
            noise_message,
        };

        Ok((
            Self {
                expected_responder,
                initiator_identity,
                initiator_noise_static,
                initiator_ratchet_secret,
                prior_handshake_hash,
                noise,
            },
            init,
        ))
    }

    pub fn process_response(
        self,
        identity: &IdentityKeypair,
        response: &HandshakeResponse,
    ) -> Result<(HandshakeFinish, DoubleRatchetState), CryptoError> {
        validate_version(response.version)?;
        if identity.public_key() != self.initiator_identity {
            return Err(CryptoError::IdentityMismatch);
        }

        let mut noise = self.noise;
        validate_noise_ephemeral(identity, &response.noise_message)?;
        let response_payload = read_noise_message(&mut noise, &response.noise_message)?;
        let response_payload: ResponderPayload = serialization::deserialize(&response_payload)
            .map_err(|_| CryptoError::MalformedMessage)?;
        if response_payload.identity != self.expected_responder {
            return Err(CryptoError::IdentityMismatch);
        }

        let responder_noise_static = remote_noise_static(&noise)?;
        identity
            .noise_static_secret()?
            .diffie_hellman(&responder_noise_static)?;
        let responder_input = responder_signature_input(
            self.prior_handshake_hash,
            self.initiator_identity,
            self.expected_responder,
            responder_noise_static,
            response_payload.ratchet_public_key,
        )?;
        verify_signature(
            &self.expected_responder,
            &responder_input,
            &response_payload.signature,
        )?;

        let prior_handshake_hash = noise_hash(&noise)?;
        let initiator_ratchet_public = self.initiator_ratchet_secret.public_key();
        let finish_payload = InitiatorPayload {
            identity: self.initiator_identity,
            ratchet_public_key: initiator_ratchet_public,
            signature: identity
                .sign(&initiator_signature_input(
                    prior_handshake_hash,
                    self.initiator_identity,
                    self.expected_responder,
                    self.initiator_noise_static,
                    responder_noise_static,
                    initiator_ratchet_public,
                )?)
                .to_vec(),
        };
        let encoded_payload =
            serialization::serialize(&finish_payload).map_err(|_| CryptoError::MalformedMessage)?;
        let noise_message = write_noise_message(&mut noise, &encoded_payload)?;
        if !noise.is_handshake_finished() {
            return Err(CryptoError::InvalidHandshakeState);
        }

        let root = derive_ratchet_root(&mut noise)?;
        let ratchet = DoubleRatchetState::initialize_initiator(
            root,
            self.initiator_ratchet_secret,
            response_payload.ratchet_public_key,
        )?;

        Ok((
            HandshakeFinish {
                version: VERSION,
                noise_message,
            },
            ratchet,
        ))
    }
}

/// Responder's pending Noise XX handshake. A session is returned only after
/// Flight 3 has authenticated and the full Noise handshake has completed.
pub struct HandshakeResponder {
    initiator_identity: IdentityPublicKey,
    responder_identity: IdentityPublicKey,
    responder_noise_static: PublicKey,
    responder_noise_static_secret: SecretKey,
    responder_ratchet_secret: SecretKey,
    prior_handshake_hash: [u8; NOISE_HASH_LENGTH],
    noise: snow::HandshakeState,
}

impl HandshakeResponder {
    pub fn respond(
        identity: &IdentityKeypair,
        expected_initiator: IdentityPublicKey,
        init: &HandshakeInit,
        replay_store: &dyn HandshakeReplayStore,
    ) -> Result<(Self, HandshakeResponse), CryptoError> {
        validate_version(init.version)?;
        if init.noise_message.len() > MAX_HANDSHAKE_MESSAGE_BYTES {
            return Err(CryptoError::MessageTooLarge);
        }

        validate_noise_ephemeral(identity, &init.noise_message)?;
        let responder_identity = identity.public_key();
        let responder_noise_static_secret = identity.noise_static_secret()?;
        let responder_noise_static = responder_noise_static_secret.public_key();
        let mut noise = build_noise_state(identity, expected_initiator, responder_identity, false)?;
        let initial_payload = read_noise_message(&mut noise, &init.noise_message)?;
        if !initial_payload.is_empty() {
            return Err(CryptoError::MalformedMessage);
        }
        let prior_handshake_hash = noise_hash(&noise)?;

        let responder_ratchet_secret = SecretKey::generate()?;
        let responder_ratchet_public = responder_ratchet_secret.public_key();
        let payload = ResponderPayload {
            identity: responder_identity,
            ratchet_public_key: responder_ratchet_public,
            signature: identity
                .sign(&responder_signature_input(
                    prior_handshake_hash,
                    expected_initiator,
                    responder_identity,
                    responder_noise_static,
                    responder_ratchet_public,
                )?)
                .to_vec(),
        };
        let encoded_payload =
            serialization::serialize(&payload).map_err(|_| CryptoError::MalformedMessage)?;
        let noise_message = write_noise_message(&mut noise, &encoded_payload)?;
        let response = HandshakeResponse {
            version: VERSION,
            noise_message,
        };

        match replay_store.check_and_record(replay_id(responder_identity, init))? {
            ReplayDecision::Inserted => {}
            ReplayDecision::AlreadyPresent => {
                return Err(CryptoError::HandshakeReplayDetected);
            }
        }

        let state = Self {
            initiator_identity: expected_initiator,
            responder_identity,
            responder_noise_static,
            responder_noise_static_secret,
            responder_ratchet_secret,
            prior_handshake_hash: noise_hash(&noise)?,
            noise,
        };

        Ok((state, response))
    }

    pub fn process_finish(
        self,
        finish: &HandshakeFinish,
    ) -> Result<DoubleRatchetState, CryptoError> {
        validate_version(finish.version)?;

        let mut noise = self.noise;
        let finish_payload = read_noise_message(&mut noise, &finish.noise_message)?;
        let finish_payload: InitiatorPayload = serialization::deserialize(&finish_payload)
            .map_err(|_| CryptoError::MalformedMessage)?;
        if finish_payload.identity != self.initiator_identity {
            return Err(CryptoError::IdentityMismatch);
        }

        let initiator_noise_static = remote_noise_static(&noise)?;
        self.responder_noise_static_secret
            .diffie_hellman(&initiator_noise_static)?;
        let initiator_input = initiator_signature_input(
            self.prior_handshake_hash,
            self.initiator_identity,
            self.responder_identity,
            initiator_noise_static,
            self.responder_noise_static,
            finish_payload.ratchet_public_key,
        )?;
        verify_signature(
            &self.initiator_identity,
            &initiator_input,
            &finish_payload.signature,
        )?;
        if !noise.is_handshake_finished() {
            return Err(CryptoError::InvalidHandshakeState);
        }

        let root = derive_ratchet_root(&mut noise)?;
        DoubleRatchetState::initialize_responder(
            root,
            self.responder_ratchet_secret,
            finish_payload.ratchet_public_key,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{HandshakeInitiator, HandshakeResponder};
    use crate::{
        identity::{IdentityKeypair, SecretKey},
        replay_store::VolatileHandshakeReplayStore,
        CryptoError,
    };

    #[test]
    fn noise_xx_authenticates_both_pinned_identities_and_initializes_ratchet() {
        let alice_identity = IdentityKeypair::from_bytes([1; 32]);
        let bob_identity = IdentityKeypair::from_bytes([2; 32]);
        let replay_store = VolatileHandshakeReplayStore::default();
        let (alice_pending, init) =
            HandshakeInitiator::start(&alice_identity, bob_identity.public_key())
                .expect("start initiator");
        let (bob_pending, response) = HandshakeResponder::respond(
            &bob_identity,
            alice_identity.public_key(),
            &init,
            &replay_store,
        )
        .expect("start responder");
        let (finish, mut alice) = alice_pending
            .process_response(&alice_identity, &response)
            .expect("authenticate responder");
        let mut bob = bob_pending
            .process_finish(&finish)
            .expect("authenticate initiator");

        let message = alice.encrypt(b"first", b"").expect("encrypt");
        assert_eq!(
            bob.decrypt(&message, b"").expect("decrypt").as_slice(),
            b"first"
        );
        let reply = bob.encrypt(b"reply", b"").expect("reply");
        assert_eq!(
            alice.decrypt(&reply, b"").expect("decrypt").as_slice(),
            b"reply"
        );
    }

    #[test]
    fn rejects_wrong_pinned_responder_identity() {
        let alice_identity = IdentityKeypair::from_bytes([11; 32]);
        let bob_identity = IdentityKeypair::from_bytes([12; 32]);
        let wrong_peer = IdentityKeypair::from_bytes([13; 32]);
        let store = VolatileHandshakeReplayStore::default();
        let (alice_pending, init) =
            HandshakeInitiator::start(&alice_identity, wrong_peer.public_key())
                .expect("start with incorrect pin");
        let (_, response) =
            HandshakeResponder::respond(&bob_identity, alice_identity.public_key(), &init, &store)
                .expect("responder creates response");

        assert!(matches!(
            alice_pending.process_response(&alice_identity, &response),
            Err(CryptoError::AuthenticationFailed) | Err(CryptoError::IdentityMismatch)
        ));
    }

    #[test]
    fn rejects_replayed_first_flight_before_returning_responder_state() {
        let alice = IdentityKeypair::from_bytes([21; 32]);
        let bob = IdentityKeypair::from_bytes([22; 32]);
        let store = VolatileHandshakeReplayStore::default();
        let (_, init) =
            HandshakeInitiator::start(&alice, bob.public_key()).expect("start initiator");

        HandshakeResponder::respond(&bob, alice.public_key(), &init, &store)
            .expect("first flight accepted");
        assert!(matches!(
            HandshakeResponder::respond(&bob, alice.public_key(), &init, &store),
            Err(CryptoError::HandshakeReplayDetected)
        ));
    }

    #[test]
    fn volatile_replay_history_is_lost_when_the_store_is_recreated() {
        let alice = IdentityKeypair::from_bytes([23; 32]);
        let bob = IdentityKeypair::from_bytes([24; 32]);
        let first_store = VolatileHandshakeReplayStore::default();
        let (_, init) =
            HandshakeInitiator::start(&alice, bob.public_key()).expect("start initiator");
        HandshakeResponder::respond(&bob, alice.public_key(), &init, &first_store)
            .expect("first store accepts flight");

        let restarted_store = VolatileHandshakeReplayStore::default();
        assert!(
            HandshakeResponder::respond(&bob, alice.public_key(), &init, &restarted_store).is_ok()
        );
    }

    #[test]
    fn rejects_noncontributory_noise_ephemeral_key() {
        let alice = IdentityKeypair::from_bytes([31; 32]);
        let bob = IdentityKeypair::from_bytes([32; 32]);
        let store = VolatileHandshakeReplayStore::default();
        let (_, mut init) =
            HandshakeInitiator::start(&alice, bob.public_key()).expect("start initiator");
        init.noise_message[..32].fill(0);

        assert!(HandshakeResponder::respond(&bob, alice.public_key(), &init, &store).is_err());
    }

    #[test]
    fn rejects_responder_signature_inside_valid_noise_ciphertext() {
        let alice = IdentityKeypair::from_bytes([41; 32]);
        let bob = IdentityKeypair::from_bytes([42; 32]);
        let (alice_pending, init) =
            HandshakeInitiator::start(&alice, bob.public_key()).expect("start initiator");
        let mut responder_noise =
            super::build_noise_state(&bob, alice.public_key(), bob.public_key(), false)
                .expect("build responder Noise state");
        let mut empty_payload = [0u8; super::MAX_NOISE_PAYLOAD_BYTES];
        responder_noise
            .read_message(&init.noise_message, &mut empty_payload)
            .expect("read first flight");
        let payload = super::ResponderPayload {
            identity: bob.public_key(),
            ratchet_public_key: SecretKey::generate()
                .expect("generate ratchet key")
                .public_key(),
            signature: vec![0; 64],
        };
        let encoded_payload =
            super::serialization::serialize(&payload).expect("encode malformed signature payload");
        let response = super::HandshakeResponse {
            version: super::VERSION,
            noise_message: super::write_noise_message(&mut responder_noise, &encoded_payload)
                .expect("encrypt malformed signature payload"),
        };

        assert!(matches!(
            alice_pending.process_response(&alice, &response),
            Err(CryptoError::InvalidSignature)
        ));
    }

    #[test]
    fn rejects_substituted_responder_identity_inside_noise_payload() {
        let alice = IdentityKeypair::from_bytes([43; 32]);
        let bob = IdentityKeypair::from_bytes([44; 32]);
        let mallory = IdentityKeypair::from_bytes([45; 32]);
        let (alice_pending, init) =
            HandshakeInitiator::start(&alice, bob.public_key()).expect("start initiator");
        let mut responder_noise =
            super::build_noise_state(&bob, alice.public_key(), bob.public_key(), false)
                .expect("build responder Noise state");
        let mut empty_payload = [0u8; super::MAX_NOISE_PAYLOAD_BYTES];
        responder_noise
            .read_message(&init.noise_message, &mut empty_payload)
            .expect("read first flight");
        let payload = super::ResponderPayload {
            identity: mallory.public_key(),
            ratchet_public_key: SecretKey::generate()
                .expect("generate ratchet key")
                .public_key(),
            signature: vec![0; 64],
        };
        let encoded_payload =
            super::serialization::serialize(&payload).expect("encode substituted identity");
        let response = super::HandshakeResponse {
            version: super::VERSION,
            noise_message: super::write_noise_message(&mut responder_noise, &encoded_payload)
                .expect("encrypt substituted identity"),
        };

        assert!(matches!(
            alice_pending.process_response(&alice, &response),
            Err(CryptoError::IdentityMismatch)
        ));
    }

    #[test]
    fn rejects_initiator_signature_inside_valid_noise_ciphertext() {
        let alice = IdentityKeypair::from_bytes([51; 32]);
        let bob = IdentityKeypair::from_bytes([52; 32]);
        let replay_store = VolatileHandshakeReplayStore::default();
        let (alice_pending, init) =
            HandshakeInitiator::start(&alice, bob.public_key()).expect("start initiator");
        let (bob_pending, response) =
            HandshakeResponder::respond(&bob, alice.public_key(), &init, &replay_store)
                .expect("create responder flight");

        let mut initiator_noise = alice_pending.noise;
        let _responder_payload =
            super::read_noise_message(&mut initiator_noise, &response.noise_message)
                .expect("read responder flight");
        let initiator_payload = super::InitiatorPayload {
            identity: alice.public_key(),
            ratchet_public_key: alice_pending.initiator_ratchet_secret.public_key(),
            signature: vec![0; 64],
        };
        let encoded_payload =
            super::serialization::serialize(&initiator_payload).expect("encode invalid signature");
        let finish = super::HandshakeFinish {
            version: super::VERSION,
            noise_message: super::write_noise_message(&mut initiator_noise, &encoded_payload)
                .expect("encrypt invalid signature payload"),
        };

        assert!(matches!(
            bob_pending.process_finish(&finish),
            Err(CryptoError::InvalidSignature)
        ));
    }

    #[test]
    fn rejects_substituted_initiator_identity_inside_noise_payload() {
        let alice = IdentityKeypair::from_bytes([53; 32]);
        let bob = IdentityKeypair::from_bytes([54; 32]);
        let mallory = IdentityKeypair::from_bytes([55; 32]);
        let replay_store = VolatileHandshakeReplayStore::default();
        let (alice_pending, init) =
            HandshakeInitiator::start(&alice, bob.public_key()).expect("start initiator");
        let (bob_pending, response) =
            HandshakeResponder::respond(&bob, alice.public_key(), &init, &replay_store)
                .expect("create responder flight");

        let mut initiator_noise = alice_pending.noise;
        super::read_noise_message(&mut initiator_noise, &response.noise_message)
            .expect("read responder flight");
        let initiator_payload = super::InitiatorPayload {
            identity: mallory.public_key(),
            ratchet_public_key: alice_pending.initiator_ratchet_secret.public_key(),
            signature: vec![0; 64],
        };
        let encoded_payload = super::serialization::serialize(&initiator_payload)
            .expect("encode substituted identity");
        let finish = super::HandshakeFinish {
            version: super::VERSION,
            noise_message: super::write_noise_message(&mut initiator_noise, &encoded_payload)
                .expect("encrypt substituted identity"),
        };

        assert!(matches!(
            bob_pending.process_finish(&finish),
            Err(CryptoError::IdentityMismatch)
        ));
    }

    #[test]
    fn rejects_wrong_handshake_flight_order_and_malformed_message() {
        assert!(matches!(
            super::serialize_init(&super::HandshakeInit {
                version: 99,
                noise_message: vec![],
            }),
            Err(CryptoError::InvalidProtocolVersion { received: 99 })
        ));
    }
}
