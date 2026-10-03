use std::collections::{HashMap, HashSet};

use serde::{
    de::{Error as DeError, SeqAccess, Visitor},
    Deserialize, Deserializer, Serialize,
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{
    aead::{self, AeadCiphertext, AeadKey},
    error::CryptoError,
    identity::{PublicKey, SecretKey},
    kdf::derive_key,
    random::random_array,
    serialization, SecretBytes,
};

const MESSAGE_VERSION: u8 = 1;
const STATE_VERSION: u8 = 2;
const ENCRYPTED_STATE_VERSION: u8 = 1;
const STATE_SNAPSHOT_AAD: &[u8] = b"aether/double-ratchet/state-snapshot/v1";
const ROOT_KDF_LABEL: &[u8] = b"aether/double-ratchet/root-chain/v1";
const CHAIN_KDF_LABEL: &[u8] = b"aether/double-ratchet/message-chain/v1";
const INITIAL_I_TO_R_LABEL: &[u8] =
    b"aether/double-ratchet/initial-chain/initiator-to-responder/v1";
const MAX_SERIALIZED_MESSAGE_BYTES: usize = 1024 * 1024;
const MAX_ASSOCIATED_DATA_BYTES: usize = 64 * 1024;
const MAX_STATE_BYTES: usize = 2 * 1024 * 1024;
const MAX_ENCRYPTED_STATE_BYTES: usize = MAX_STATE_BYTES + 64;
const MAX_PERSISTED_SKIPPED_KEYS: usize = 20_000;
const MAX_CIPHERTEXT_BYTES: usize = 1024 * 1024;
const DEFAULT_MAX_SKIPPED_KEYS: usize = 2_000;

/// Public, versioned ratchet header. It is included in AEAD associated data.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct RatchetHeader {
    pub version: u8,
    pub ratchet_public_key: PublicKey,
    pub previous_chain_length: u32,
    pub message_number: u32,
}

/// Public network message. It contains no secret ratchet state.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RatchetMessage {
    pub header: RatchetHeader,
    pub ciphertext: AeadCiphertext,
}

#[derive(Eq, Hash, PartialEq)]
struct SkippedKeyId {
    ratchet_public_key: [u8; 32],
    message_number: u32,
}

#[derive(Deserialize, Serialize, Zeroize, ZeroizeOnDrop)]
struct SkippedKeySnapshot {
    ratchet_public_key: [u8; 32],
    message_number: u32,
    message_key: [u8; 32],
}

#[derive(Deserialize, Serialize, Zeroize)]
struct RatchetStateSnapshot {
    version: u8,
    root_key: [u8; 32],
    sending_chain_key: Option<[u8; 32]>,
    receiving_chain_key: Option<[u8; 32]>,
    local_ratchet_key: [u8; 32],
    remote_ratchet_key: [u8; 32],
    sending_message_number: u32,
    receiving_message_number: u32,
    previous_sending_chain_length: u32,
    skipped_message_keys: BoundedSkippedKeys,
    retired_remote_keys: BoundedRetiredKeys,
    max_skipped_message_keys: u32,
}

#[derive(Deserialize, Serialize)]
struct EncryptedRatchetState {
    version: u8,
    ciphertext: AeadCiphertext,
}

struct BoundedSkippedKeys(Vec<SkippedKeySnapshot>);

impl Serialize for BoundedSkippedKeys {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl Zeroize for BoundedSkippedKeys {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

struct BoundedRetiredKeys(Vec<[u8; 32]>);

impl Serialize for BoundedRetiredKeys {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl Zeroize for BoundedRetiredKeys {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl<'de> Deserialize<'de> for BoundedRetiredKeys {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct RetiredKeysVisitor;

        impl<'de> Visitor<'de> for RetiredKeysVisitor {
            type Value = BoundedRetiredKeys;

            fn expecting(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                formatter.write_str("at most 20,000 retired ratchet public keys")
            }

            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut sequence: A,
            ) -> Result<Self::Value, A::Error> {
                let mut keys = Vec::new();
                while let Some(key) = sequence.next_element()? {
                    if keys.len() == MAX_PERSISTED_SKIPPED_KEYS {
                        return Err(A::Error::custom("too many retired ratchet keys"));
                    }
                    keys.push(key);
                }
                Ok(BoundedRetiredKeys(keys))
            }
        }

        deserializer.deserialize_seq(RetiredKeysVisitor)
    }
}

impl<'de> Deserialize<'de> for BoundedSkippedKeys {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct BoundedSkippedKeysVisitor;

        impl<'de> Visitor<'de> for BoundedSkippedKeysVisitor {
            type Value = BoundedSkippedKeys;

            fn expecting(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                formatter.write_str("at most 20,000 skipped message keys")
            }

            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut sequence: A,
            ) -> Result<Self::Value, A::Error> {
                let mut keys = Vec::new();
                while let Some(key) = sequence.next_element()? {
                    if keys.len() == MAX_PERSISTED_SKIPPED_KEYS {
                        return Err(A::Error::custom("too many skipped message keys"));
                    }
                    keys.push(key);
                }
                Ok(BoundedSkippedKeys(keys))
            }
        }

        deserializer.deserialize_seq(BoundedSkippedKeysVisitor)
    }
}

impl Drop for RatchetStateSnapshot {
    fn drop(&mut self) {
        self.version.zeroize();
        self.root_key.zeroize();
        self.sending_chain_key.zeroize();
        self.receiving_chain_key.zeroize();
        self.local_ratchet_key.zeroize();
        self.remote_ratchet_key.zeroize();
        self.sending_message_number.zeroize();
        self.receiving_message_number.zeroize();
        self.previous_sending_chain_length.zeroize();
        self.max_skipped_message_keys.zeroize();
        self.skipped_message_keys.zeroize();
        self.retired_remote_keys.zeroize();
    }
}

struct ChainKey(SecretBytes);

impl ChainKey {
    fn duplicate(&self) -> Self {
        Self(self.0.duplicate())
    }
}

/// Local, non-serializable Double Ratchet state.
///
/// State changes are applied to a temporary copy and committed only after
/// successful authentication when decrypting.
pub struct DoubleRatchetState {
    root_key: SecretBytes,
    sending_chain_key: Option<ChainKey>,
    receiving_chain_key: Option<ChainKey>,
    local_ratchet_key: SecretKey,
    remote_ratchet_key: PublicKey,
    sending_message_number: u32,
    receiving_message_number: u32,
    previous_sending_chain_length: u32,
    skipped_message_keys: HashMap<SkippedKeyId, AeadKey>,
    retired_remote_keys: HashSet<[u8; 32]>,
    max_skipped_message_keys: usize,
}

impl DoubleRatchetState {
    pub(crate) fn initialize_initiator(
        root_key: SecretBytes,
        local_ratchet_key: SecretKey,
        remote_ratchet_key: PublicKey,
    ) -> Result<Self, CryptoError> {
        Self::initialize(root_key, local_ratchet_key, remote_ratchet_key, true)
    }

    pub(crate) fn initialize_responder(
        root_key: SecretBytes,
        local_ratchet_key: SecretKey,
        remote_ratchet_key: PublicKey,
    ) -> Result<Self, CryptoError> {
        Self::initialize(root_key, local_ratchet_key, remote_ratchet_key, false)
    }

    fn initialize(
        root_key: SecretBytes,
        local_ratchet_key: SecretKey,
        remote_ratchet_key: PublicKey,
        initiator: bool,
    ) -> Result<Self, CryptoError> {
        let initial_shared_secret = local_ratchet_key.diffie_hellman(&remote_ratchet_key)?;
        let initial_chain = derive_key(
            Some(initial_shared_secret.as_slice()),
            root_key.as_slice(),
            INITIAL_I_TO_R_LABEL,
            32,
        )?;

        Ok(Self {
            root_key,
            sending_chain_key: initiator.then_some(ChainKey(initial_chain.duplicate())),
            receiving_chain_key: (!initiator).then_some(ChainKey(initial_chain)),
            local_ratchet_key,
            remote_ratchet_key,
            sending_message_number: 0,
            receiving_message_number: 0,
            previous_sending_chain_length: 0,
            skipped_message_keys: HashMap::new(),
            retired_remote_keys: HashSet::new(),
            max_skipped_message_keys: DEFAULT_MAX_SKIPPED_KEYS,
        })
    }

    /// Sets the maximum number of retained out-of-order message keys.
    pub(crate) fn set_max_skipped_message_keys(&mut self, limit: usize) -> Result<(), CryptoError> {
        if limit > MAX_PERSISTED_SKIPPED_KEYS {
            return Err(CryptoError::SkippedMessageKeyLimitExceeded {
                limit: MAX_PERSISTED_SKIPPED_KEYS,
            });
        }
        self.max_skipped_message_keys = limit;
        Ok(())
    }

    pub fn skipped_message_key_count(&self) -> usize {
        self.skipped_message_keys.len()
    }

    /// Exports an authenticated-encrypted snapshot using a caller-managed
    /// 32-byte storage key. The key is never included in the returned bytes.
    pub fn export_state(&self, storage_key: &[u8; 32]) -> Result<Vec<u8>, CryptoError> {
        if self.skipped_message_keys.len() > self.max_skipped_message_keys
            || self.max_skipped_message_keys > MAX_PERSISTED_SKIPPED_KEYS
        {
            return Err(CryptoError::MessageTooLarge);
        }
        let max_skipped_message_keys = u32::try_from(self.max_skipped_message_keys)
            .map_err(|_| CryptoError::MessageTooLarge)?;
        let mut skipped_message_keys: Vec<_> = self
            .skipped_message_keys
            .iter()
            .map(|(id, key)| SkippedKeySnapshot {
                ratchet_public_key: id.ratchet_public_key,
                message_number: id.message_number,
                message_key: key.export_bytes(),
            })
            .collect();
        skipped_message_keys.sort_by_key(|item| (item.ratchet_public_key, item.message_number));

        let snapshot = Zeroizing::new(RatchetStateSnapshot {
            version: STATE_VERSION,
            root_key: secret_array(&self.root_key)?,
            sending_chain_key: self
                .sending_chain_key
                .as_ref()
                .map(|chain| secret_array(&chain.0))
                .transpose()?,
            receiving_chain_key: self
                .receiving_chain_key
                .as_ref()
                .map(|chain| secret_array(&chain.0))
                .transpose()?,
            local_ratchet_key: self.local_ratchet_key.export_bytes(),
            remote_ratchet_key: *self.remote_ratchet_key.as_bytes(),
            sending_message_number: self.sending_message_number,
            receiving_message_number: self.receiving_message_number,
            previous_sending_chain_length: self.previous_sending_chain_length,
            skipped_message_keys: BoundedSkippedKeys(skipped_message_keys),
            retired_remote_keys: BoundedRetiredKeys({
                let mut keys: Vec<_> = self.retired_remote_keys.iter().copied().collect();
                keys.sort_unstable();
                keys
            }),
            max_skipped_message_keys,
        });
        let encoded = Zeroizing::new(
            serialization::serialize(&*snapshot).map_err(|_| CryptoError::MalformedMessage)?,
        );
        if encoded.len() > MAX_STATE_BYTES {
            return Err(CryptoError::MessageTooLarge);
        }
        let key = AeadKey::from_bytes(*storage_key);
        let ciphertext = aead::encrypt(&key, &encoded, STATE_SNAPSHOT_AAD)?;
        let encrypted = EncryptedRatchetState {
            version: ENCRYPTED_STATE_VERSION,
            ciphertext,
        };
        let encoded =
            serialization::serialize(&encrypted).map_err(|_| CryptoError::MalformedMessage)?;
        if encoded.len() > MAX_ENCRYPTED_STATE_BYTES {
            return Err(CryptoError::MessageTooLarge);
        }
        Ok(encoded)
    }

    /// Authenticates and decrypts a persisted snapshot before parsing its
    /// secret state. The caller must provide the same protected 32-byte key
    /// used for export.
    pub fn import_state(encoded: &[u8], storage_key: &[u8; 32]) -> Result<Self, CryptoError> {
        if encoded.len() > MAX_ENCRYPTED_STATE_BYTES {
            return Err(CryptoError::MessageTooLarge);
        }
        let encrypted: EncryptedRatchetState =
            serialization::deserialize(encoded).map_err(|_| CryptoError::MalformedMessage)?;
        if encrypted.version != ENCRYPTED_STATE_VERSION {
            return Err(CryptoError::InvalidProtocolVersion {
                received: encrypted.version,
            });
        }
        let key = AeadKey::from_bytes(*storage_key);
        let plaintext = aead::decrypt(&key, &encrypted.ciphertext, STATE_SNAPSHOT_AAD)?;
        if plaintext.as_slice().len() > MAX_STATE_BYTES {
            return Err(CryptoError::MessageTooLarge);
        }
        let snapshot: Zeroizing<RatchetStateSnapshot> = Zeroizing::new(
            serialization::deserialize(plaintext.as_slice())
                .map_err(|_| CryptoError::MalformedMessage)?,
        );
        if snapshot.version != STATE_VERSION {
            return Err(CryptoError::InvalidProtocolVersion {
                received: snapshot.version,
            });
        }
        if snapshot.max_skipped_message_keys > MAX_PERSISTED_SKIPPED_KEYS as u32
            || snapshot.sending_chain_key.is_none() && snapshot.sending_message_number != 0
            || snapshot.receiving_chain_key.is_none() && snapshot.receiving_message_number != 0
        {
            return Err(CryptoError::MalformedMessage);
        }

        let max_skipped_message_keys = usize::try_from(snapshot.max_skipped_message_keys)
            .map_err(|_| CryptoError::MalformedMessage)?;
        if snapshot.skipped_message_keys.0.len() > max_skipped_message_keys {
            return Err(CryptoError::MalformedMessage);
        }
        if snapshot.retired_remote_keys.0.len() > MAX_PERSISTED_SKIPPED_KEYS
            || snapshot.retired_remote_keys.0.len()
                != snapshot
                    .retired_remote_keys
                    .0
                    .iter()
                    .collect::<HashSet<_>>()
                    .len()
        {
            return Err(CryptoError::MalformedMessage);
        }
        let local_ratchet_key = SecretKey::from_bytes(snapshot.local_ratchet_key);
        let remote_ratchet_key = PublicKey::from_bytes(snapshot.remote_ratchet_key);
        local_ratchet_key.diffie_hellman(&remote_ratchet_key)?;
        let retired_remote_keys: HashSet<_> =
            snapshot.retired_remote_keys.0.iter().copied().collect();
        if retired_remote_keys.contains(remote_ratchet_key.as_bytes()) {
            return Err(CryptoError::MalformedMessage);
        }
        let mut skipped_message_keys =
            HashMap::with_capacity(snapshot.skipped_message_keys.0.len());
        for skipped in &snapshot.skipped_message_keys.0 {
            let id = SkippedKeyId {
                ratchet_public_key: skipped.ratchet_public_key,
                message_number: skipped.message_number,
            };
            if skipped_message_keys
                .insert(id, AeadKey::from_bytes(skipped.message_key))
                .is_some()
            {
                return Err(CryptoError::MalformedMessage);
            }
        }

        Ok(Self {
            root_key: SecretBytes::from_array(snapshot.root_key),
            sending_chain_key: snapshot
                .sending_chain_key
                .map(|key| ChainKey(SecretBytes::from_array(key))),
            receiving_chain_key: snapshot
                .receiving_chain_key
                .map(|key| ChainKey(SecretBytes::from_array(key))),
            local_ratchet_key,
            remote_ratchet_key,
            sending_message_number: snapshot.sending_message_number,
            receiving_message_number: snapshot.receiving_message_number,
            previous_sending_chain_length: snapshot.previous_sending_chain_length,
            skipped_message_keys,
            retired_remote_keys,
            max_skipped_message_keys,
        })
    }

    /// Encrypts using the current sending chain, rotating DH when this side has
    /// not yet established a sending chain (the responder's initial turn).
    pub fn encrypt(
        &mut self,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<RatchetMessage, CryptoError> {
        if associated_data.len() > MAX_ASSOCIATED_DATA_BYTES {
            return Err(CryptoError::MessageTooLarge);
        }
        if plaintext.len() > MAX_SERIALIZED_MESSAGE_BYTES {
            return Err(CryptoError::MessageTooLarge);
        }
        if self.sending_message_number == u32::MAX {
            return Err(CryptoError::MessageCounterExhausted);
        }

        let mut next = self.duplicate();
        if next.sending_chain_key.is_none() {
            next.rotate_sending_chain()?;
        }

        let header = RatchetHeader {
            version: MESSAGE_VERSION,
            ratchet_public_key: next.local_ratchet_key.public_key(),
            previous_chain_length: next.previous_sending_chain_length,
            message_number: next.sending_message_number,
        };
        let (next_chain_key, message_key) = kdf_chain(
            next.sending_chain_key
                .as_ref()
                .ok_or(CryptoError::InvalidHandshakeState)?,
        )?;
        let aead_key = aead_key_from_secret(&message_key)?;
        let aad = associated_data_for(&header, associated_data)?;
        let ciphertext = aead::encrypt(&aead_key, plaintext, &aad)?;

        next.sending_chain_key = Some(next_chain_key);
        next.sending_message_number = next
            .sending_message_number
            .checked_add(1)
            .ok_or(CryptoError::MessageCounterExhausted)?;
        *self = next;

        Ok(RatchetMessage { header, ciphertext })
    }

    /// Authenticates and decrypts a message. Invalid messages leave this state unchanged.
    pub fn decrypt(
        &mut self,
        message: &RatchetMessage,
        associated_data: &[u8],
    ) -> Result<SecretBytes, CryptoError> {
        validate_message(message, associated_data)?;

        let mut next = self.duplicate();
        let header = message.header;
        let skipped_id = skipped_key_id(&header);
        if let Some(key) = next.skipped_message_keys.remove(&skipped_id) {
            let aad = associated_data_for(&header, associated_data)?;
            let plaintext = aead::decrypt(&key, &message.ciphertext, &aad)?;
            *self = next;
            return Ok(plaintext);
        }

        if header.ratchet_public_key != next.remote_ratchet_key
            && next
                .retired_remote_keys
                .contains(header.ratchet_public_key.as_bytes())
        {
            return Err(CryptoError::ReplayOrExpiredMessage);
        }

        if header.ratchet_public_key != next.remote_ratchet_key {
            next.skip_message_keys(header.previous_chain_length)?;
            next.dh_ratchet(header.ratchet_public_key)?;
        }

        if header.message_number < next.receiving_message_number {
            return Err(CryptoError::ReplayOrExpiredMessage);
        }

        next.skip_message_keys(header.message_number)?;
        let (next_chain_key, message_key) = kdf_chain(
            next.receiving_chain_key
                .as_ref()
                .ok_or(CryptoError::InvalidHandshakeState)?,
        )?;
        let aead_key = aead_key_from_secret(&message_key)?;
        let aad = associated_data_for(&header, associated_data)?;
        let plaintext = aead::decrypt(&aead_key, &message.ciphertext, &aad)?;

        next.receiving_chain_key = Some(next_chain_key);
        next.receiving_message_number = next
            .receiving_message_number
            .checked_add(1)
            .ok_or(CryptoError::MessageCounterExhausted)?;
        *self = next;

        Ok(plaintext)
    }

    pub fn serialize_message(message: &RatchetMessage) -> Result<Vec<u8>, CryptoError> {
        if message.ciphertext.ciphertext().len() > MAX_SERIALIZED_MESSAGE_BYTES {
            return Err(CryptoError::MessageTooLarge);
        }
        let encoded =
            serialization::serialize(message).map_err(|_| CryptoError::MalformedMessage)?;
        if encoded.len() > MAX_SERIALIZED_MESSAGE_BYTES {
            return Err(CryptoError::MessageTooLarge);
        }
        Ok(encoded)
    }

    pub fn deserialize_message(encoded: &[u8]) -> Result<RatchetMessage, CryptoError> {
        if encoded.len() > MAX_SERIALIZED_MESSAGE_BYTES {
            return Err(CryptoError::MessageTooLarge);
        }
        let message: RatchetMessage =
            serialization::deserialize(encoded).map_err(|_| CryptoError::MalformedMessage)?;
        validate_message(&message, &[])?;
        Ok(message)
    }

    fn rotate_sending_chain(&mut self) -> Result<(), CryptoError> {
        self.previous_sending_chain_length = self.sending_message_number;
        self.sending_message_number = 0;
        self.local_ratchet_key = SecretKey::from_bytes(random_array()?);
        let shared_secret = self
            .local_ratchet_key
            .diffie_hellman(&self.remote_ratchet_key)?;
        let (root_key, chain_key) = kdf_root(&self.root_key, &shared_secret)?;
        self.root_key = root_key;
        self.sending_chain_key = Some(chain_key);
        Ok(())
    }

    fn dh_ratchet(&mut self, remote_key: PublicKey) -> Result<(), CryptoError> {
        if self.retired_remote_keys.len() >= MAX_PERSISTED_SKIPPED_KEYS {
            return Err(CryptoError::RatchetGenerationLimitExceeded {
                limit: MAX_PERSISTED_SKIPPED_KEYS,
            });
        }
        self.retired_remote_keys
            .insert(*self.remote_ratchet_key.as_bytes());
        self.previous_sending_chain_length = self.sending_message_number;
        self.sending_message_number = 0;
        self.receiving_message_number = 0;
        self.remote_ratchet_key = remote_key;

        let receive_shared_secret = self
            .local_ratchet_key
            .diffie_hellman(&self.remote_ratchet_key)?;
        let (root_key, receiving_chain_key) = kdf_root(&self.root_key, &receive_shared_secret)?;
        self.root_key = root_key;
        self.receiving_chain_key = Some(receiving_chain_key);

        self.local_ratchet_key = SecretKey::from_bytes(random_array()?);
        let send_shared_secret = self
            .local_ratchet_key
            .diffie_hellman(&self.remote_ratchet_key)?;
        let (root_key, sending_chain_key) = kdf_root(&self.root_key, &send_shared_secret)?;
        self.root_key = root_key;
        self.sending_chain_key = Some(sending_chain_key);
        Ok(())
    }

    fn skip_message_keys(&mut self, until: u32) -> Result<(), CryptoError> {
        if until < self.receiving_message_number {
            return Err(CryptoError::ReplayOrExpiredMessage);
        }
        let count = (until - self.receiving_message_number) as usize;
        if count
            > self
                .max_skipped_message_keys
                .saturating_sub(self.skipped_message_keys.len())
        {
            return Err(CryptoError::SkippedMessageKeyLimitExceeded {
                limit: self.max_skipped_message_keys,
            });
        }
        if count == 0 {
            return Ok(());
        }
        if self.receiving_chain_key.is_none() {
            return Err(CryptoError::InvalidHandshakeState);
        }

        while self.receiving_message_number < until {
            let (next_chain, message_key) = kdf_chain(
                self.receiving_chain_key
                    .as_ref()
                    .ok_or(CryptoError::InvalidHandshakeState)?,
            )?;
            let id = SkippedKeyId {
                ratchet_public_key: *self.remote_ratchet_key.as_bytes(),
                message_number: self.receiving_message_number,
            };
            self.skipped_message_keys
                .insert(id, aead_key_from_secret(&message_key)?);
            self.receiving_chain_key = Some(next_chain);
            self.receiving_message_number = self
                .receiving_message_number
                .checked_add(1)
                .ok_or(CryptoError::MessageCounterExhausted)?;
        }

        Ok(())
    }

    fn duplicate(&self) -> Self {
        Self {
            root_key: self.root_key.duplicate(),
            sending_chain_key: self.sending_chain_key.as_ref().map(ChainKey::duplicate),
            receiving_chain_key: self.receiving_chain_key.as_ref().map(ChainKey::duplicate),
            local_ratchet_key: self.local_ratchet_key.duplicate(),
            remote_ratchet_key: self.remote_ratchet_key,
            sending_message_number: self.sending_message_number,
            receiving_message_number: self.receiving_message_number,
            previous_sending_chain_length: self.previous_sending_chain_length,
            skipped_message_keys: self
                .skipped_message_keys
                .iter()
                .map(|(id, key)| {
                    (
                        SkippedKeyId {
                            ratchet_public_key: id.ratchet_public_key,
                            message_number: id.message_number,
                        },
                        key.duplicate(),
                    )
                })
                .collect(),
            retired_remote_keys: self.retired_remote_keys.clone(),
            max_skipped_message_keys: self.max_skipped_message_keys,
        }
    }
}

impl core::fmt::Debug for DoubleRatchetState {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("DoubleRatchetState")
            .field("root_key", &"[REDACTED]")
            .field(
                "sending_chain_key",
                &self.sending_chain_key.as_ref().map(|_| "[REDACTED]"),
            )
            .field(
                "receiving_chain_key",
                &self.receiving_chain_key.as_ref().map(|_| "[REDACTED]"),
            )
            .field("local_ratchet_key", &"[REDACTED]")
            .field("remote_ratchet_key", &self.remote_ratchet_key)
            .field("sending_message_number", &self.sending_message_number)
            .field("receiving_message_number", &self.receiving_message_number)
            .field(
                "previous_sending_chain_length",
                &self.previous_sending_chain_length,
            )
            .field(
                "skipped_message_key_count",
                &self.skipped_message_keys.len(),
            )
            .finish()
    }
}

fn validate_message(message: &RatchetMessage, associated_data: &[u8]) -> Result<(), CryptoError> {
    if message.header.version != MESSAGE_VERSION {
        return Err(CryptoError::InvalidProtocolVersion {
            received: message.header.version,
        });
    }
    if message.ciphertext.ciphertext().len() > MAX_CIPHERTEXT_BYTES
        || associated_data.len() > MAX_ASSOCIATED_DATA_BYTES
    {
        return Err(CryptoError::MessageTooLarge);
    }
    Ok(())
}

fn skipped_key_id(header: &RatchetHeader) -> SkippedKeyId {
    SkippedKeyId {
        ratchet_public_key: *header.ratchet_public_key.as_bytes(),
        message_number: header.message_number,
    }
}

fn associated_data_for(
    header: &RatchetHeader,
    associated_data: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let encoded_header =
        serialization::serialize(header).map_err(|_| CryptoError::MalformedMessage)?;
    let header_length =
        u32::try_from(encoded_header.len()).map_err(|_| CryptoError::MessageTooLarge)?;
    let external_length =
        u64::try_from(associated_data.len()).map_err(|_| CryptoError::MessageTooLarge)?;
    let mut aad = Vec::with_capacity(16 + encoded_header.len() + associated_data.len());
    aad.extend_from_slice(b"aether/dr/message/v1");
    aad.extend_from_slice(&header_length.to_le_bytes());
    aad.extend_from_slice(&encoded_header);
    aad.extend_from_slice(&external_length.to_le_bytes());
    aad.extend_from_slice(associated_data);
    Ok(aad)
}

fn kdf_root(
    root_key: &SecretBytes,
    dh_output: &SecretBytes,
) -> Result<(SecretBytes, ChainKey), CryptoError> {
    let mut material = derive_key(
        Some(root_key.as_slice()),
        dh_output.as_slice(),
        ROOT_KDF_LABEL,
        64,
    )?;
    let (root_bytes, chain_bytes) = material.as_slice().split_at(32);
    let new_root = SecretBytes::from_vec(root_bytes.to_vec());
    let chain_key = ChainKey(SecretBytes::from_vec(chain_bytes.to_vec()));
    material.as_mut_slice().fill(0);
    Ok((new_root, chain_key))
}

fn kdf_chain(chain_key: &ChainKey) -> Result<(ChainKey, SecretBytes), CryptoError> {
    let mut material = derive_key(None, chain_key.0.as_slice(), CHAIN_KDF_LABEL, 64)?;
    let (next_chain, message_key) = material.as_slice().split_at(32);
    let next_chain = ChainKey(SecretBytes::from_vec(next_chain.to_vec()));
    let message_key = SecretBytes::from_vec(message_key.to_vec());
    material.as_mut_slice().fill(0);
    Ok((next_chain, message_key))
}

fn aead_key_from_secret(secret: &SecretBytes) -> Result<AeadKey, CryptoError> {
    let bytes: [u8; 32] = secret
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::InvalidKeyLength { expected: 32 })?;
    Ok(AeadKey::from_bytes(bytes))
}

fn secret_array(secret: &SecretBytes) -> Result<[u8; 32], CryptoError> {
    secret
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::InvalidKeyLength { expected: 32 })
}

#[cfg(test)]
mod tests {
    use crate::{
        aead::{self, AeadKey},
        error::CryptoError,
        handshake::{HandshakeInitiator, HandshakeResponder},
        identity::IdentityKeypair,
        ratchet::{
            DoubleRatchetState, EncryptedRatchetState, RatchetMessage, ENCRYPTED_STATE_VERSION,
            STATE_SNAPSHOT_AAD, STATE_VERSION,
        },
        replay_store::VolatileHandshakeReplayStore,
        serialization,
    };

    fn established_pair() -> (DoubleRatchetState, DoubleRatchetState) {
        let alice_identity = IdentityKeypair::from_bytes([41; 32]);
        let bob_identity = IdentityKeypair::from_bytes([42; 32]);
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
        let (finish, alice) = alice_pending
            .process_response(&alice_identity, &response)
            .expect("response authenticates");
        let bob = bob_pending
            .process_finish(&finish)
            .expect("finish authenticates");
        (alice, bob)
    }

    #[test]
    fn supports_bidirectional_multi_message_ratchet() {
        let (mut alice, mut bob) = established_pair();
        for text in [b"a0".as_slice(), b"a1", b"a2"] {
            let message = alice.encrypt(text, b"room").expect("encrypt");
            assert_eq!(
                bob.decrypt(&message, b"room").expect("decrypt").as_slice(),
                text
            );
        }
        for text in [b"b0".as_slice(), b"b1"] {
            let message = bob.encrypt(text, b"room").expect("encrypt");
            assert_eq!(
                alice
                    .decrypt(&message, b"room")
                    .expect("decrypt")
                    .as_slice(),
                text
            );
        }
        let message = alice.encrypt(b"a3", b"room").expect("encrypt");
        assert_eq!(
            bob.decrypt(&message, b"room").expect("decrypt").as_slice(),
            b"a3"
        );
    }

    #[test]
    fn decrypts_out_of_order_and_rejects_replay() {
        let (mut alice, mut bob) = established_pair();
        let messages = [
            alice.encrypt(b"zero", b"").expect("encrypt"),
            alice.encrypt(b"one", b"").expect("encrypt"),
            alice.encrypt(b"two", b"").expect("encrypt"),
        ];
        assert_eq!(
            bob.decrypt(&messages[2], b"").expect("decrypt").as_slice(),
            b"two"
        );
        assert_eq!(bob.skipped_message_key_count(), 2);
        assert_eq!(
            bob.decrypt(&messages[0], b"").expect("decrypt").as_slice(),
            b"zero"
        );
        assert_eq!(
            bob.decrypt(&messages[1], b"").expect("decrypt").as_slice(),
            b"one"
        );
        assert!(matches!(
            bob.decrypt(&messages[1], b""),
            Err(CryptoError::ReplayOrExpiredMessage)
        ));
    }

    #[test]
    fn drains_one_chain_backwards_after_receiving_its_last_message() {
        let (mut alice, mut bob) = established_pair();
        let messages = [
            alice.encrypt(b"A0", b"").expect("encrypt A0"),
            alice.encrypt(b"A1", b"").expect("encrypt A1"),
            alice.encrypt(b"A2", b"").expect("encrypt A2"),
            alice.encrypt(b"A3", b"").expect("encrypt A3"),
        ];

        assert_eq!(
            bob.decrypt(&messages[3], b"")
                .expect("receive A3")
                .as_slice(),
            b"A3"
        );
        assert_eq!(bob.skipped_message_key_count(), 3);
        for (index, expected) in [(1, b"A1".as_slice()), (2, b"A2"), (0, b"A0")] {
            assert_eq!(
                bob.decrypt(&messages[index], b"")
                    .expect("receive skipped")
                    .as_slice(),
                expected
            );
        }
        assert_eq!(bob.skipped_message_key_count(), 0);
    }

    #[test]
    fn crossed_initial_sends_are_decryptable() {
        let (mut alice, mut bob) = established_pair();
        let from_alice = alice.encrypt(b"alice concurrent", b"").expect("encrypt");
        let from_bob = bob.encrypt(b"bob concurrent", b"").expect("encrypt");

        assert_eq!(
            bob.decrypt(&from_alice, b"")
                .expect("decrypt Alice")
                .as_slice(),
            b"alice concurrent"
        );
        assert_eq!(
            alice
                .decrypt(&from_bob, b"")
                .expect("decrypt Bob")
                .as_slice(),
            b"bob concurrent"
        );
    }

    #[test]
    fn retains_old_chain_keys_across_dh_ratchet_transition() {
        let (mut alice, mut bob) = established_pair();
        let first = alice.encrypt(b"first", b"").expect("encrypt");
        bob.decrypt(&first, b"").expect("decrypt");

        let b0 = bob.encrypt(b"b0", b"").expect("encrypt");
        alice.decrypt(&b0, b"").expect("decrypt");
        let a1 = alice.encrypt(b"a1", b"").expect("encrypt");
        let b1 = bob.encrypt(b"b1 delayed", b"").expect("encrypt");
        bob.decrypt(&a1, b"").expect("DH ratchet and decrypt");
        let b2 = bob.encrypt(b"b2 new chain", b"").expect("encrypt");

        assert_eq!(
            alice
                .decrypt(&b2, b"")
                .expect("skip old chain and ratchet")
                .as_slice(),
            b"b2 new chain"
        );
        assert_eq!(
            alice
                .decrypt(&b1, b"")
                .expect("use retained old chain key")
                .as_slice(),
            b"b1 delayed"
        );
    }

    #[test]
    fn drains_skipped_messages_from_multiple_old_ratchet_chains() {
        let (mut alice, mut bob) = established_pair();

        let a0 = alice.encrypt(b"A0", b"").expect("encrypt A0");
        let a1 = alice.encrypt(b"A1", b"").expect("encrypt A1");
        let a2 = alice.encrypt(b"A2", b"").expect("encrypt A2");
        let a3 = alice.encrypt(b"A3", b"").expect("encrypt A3");
        assert_eq!(bob.decrypt(&a3, b"").expect("receive A3").as_slice(), b"A3");

        let b0 = bob.encrypt(b"B0", b"").expect("encrypt B0");
        let b1 = bob.encrypt(b"B1", b"").expect("encrypt B1");
        assert_eq!(
            alice.decrypt(&b1, b"").expect("receive B1").as_slice(),
            b"B1"
        );

        let a4 = alice.encrypt(b"A4", b"").expect("encrypt A4");
        let a5 = alice.encrypt(b"A5", b"").expect("encrypt A5");
        assert_eq!(bob.decrypt(&a5, b"").expect("receive A5").as_slice(), b"A5");

        let b2 = bob.encrypt(b"B2", b"").expect("encrypt B2");
        let b3 = bob.encrypt(b"B3", b"").expect("encrypt B3");
        assert_eq!(
            alice.decrypt(&b3, b"").expect("receive B3").as_slice(),
            b"B3"
        );

        let a6 = alice.encrypt(b"A6", b"").expect("encrypt A6");
        assert_eq!(bob.decrypt(&a6, b"").expect("receive A6").as_slice(), b"A6");

        for (message, expected) in [
            (&a1, b"A1".as_slice()),
            (&a2, b"A2"),
            (&a0, b"A0"),
            (&b0, b"B0"),
            (&a4, b"A4"),
            (&b2, b"B2"),
        ] {
            let plaintext = match message.header.ratchet_public_key {
                _ if message.header.ratchet_public_key == a0.header.ratchet_public_key => {
                    bob.decrypt(message, b"")
                }
                _ if message.header.ratchet_public_key == a4.header.ratchet_public_key => {
                    bob.decrypt(message, b"")
                }
                _ => alice.decrypt(message, b""),
            }
            .expect("delayed previous-chain message remains decryptable");
            assert_eq!(plaintext.as_slice(), expected);
        }

        assert_eq!(bob.skipped_message_key_count(), 0);
        assert_eq!(alice.skipped_message_key_count(), 0);
    }

    #[test]
    fn authenticates_header_body_and_external_associated_data() {
        let (mut alice, mut bob) = established_pair();
        let message = alice.encrypt(b"content", b"bound").expect("encrypt");

        assert!(matches!(
            bob.decrypt(&message, b"changed"),
            Err(CryptoError::AuthenticationFailed)
        ));
        let mut changed_body = message.clone();
        changed_body.ciphertext.corrupt_first_ciphertext_byte();
        assert!(matches!(
            bob.decrypt(&changed_body, b"bound"),
            Err(CryptoError::AuthenticationFailed)
        ));
        let mut changed_header = message.clone();
        changed_header.header.message_number += 1;
        assert!(matches!(
            bob.decrypt(&changed_header, b"bound"),
            Err(CryptoError::AuthenticationFailed)
        ));
        assert_eq!(
            bob.decrypt(&message, b"bound")
                .expect("original unchanged")
                .as_slice(),
            b"content"
        );
    }

    #[test]
    fn failed_authentication_does_not_advance_state() {
        let (mut alice, mut bob) = established_pair();
        let message = alice.encrypt(b"content", b"").expect("encrypt");
        let mut altered = message.clone();
        altered.ciphertext.corrupt_first_ciphertext_byte();

        assert!(matches!(
            bob.decrypt(&altered, b""),
            Err(CryptoError::AuthenticationFailed)
        ));
        assert_eq!(
            bob.decrypt(&message, b"")
                .expect("retry valid message")
                .as_slice(),
            b"content"
        );
    }

    #[test]
    fn skipped_key_limit_is_enforced_without_state_change() {
        let (mut alice, mut bob) = established_pair();
        bob.set_max_skipped_message_keys(1)
            .expect("limit is within the supported bound");
        let first = alice.encrypt(b"first", b"").expect("encrypt");
        let _second = alice.encrypt(b"second", b"").expect("encrypt");
        let third = alice.encrypt(b"third", b"").expect("encrypt");

        assert!(matches!(
            bob.decrypt(&third, b""),
            Err(CryptoError::SkippedMessageKeyLimitExceeded { limit: 1 })
        ));
        assert_eq!(bob.skipped_message_key_count(), 0);
        assert_eq!(
            bob.decrypt(&first, b"")
                .expect("state unchanged")
                .as_slice(),
            b"first"
        );
    }

    #[test]
    fn message_serialization_round_trips_and_rejects_malformed_input() {
        let (mut alice, mut bob) = established_pair();
        let message = alice.encrypt(b"serialized", b"").expect("encrypt");
        let encoded = DoubleRatchetState::serialize_message(&message).expect("serialize");
        let decoded = DoubleRatchetState::deserialize_message(&encoded).expect("deserialize");
        assert_eq!(
            bob.decrypt(&decoded, b"").expect("decrypt").as_slice(),
            b"serialized"
        );
        assert!(matches!(
            DoubleRatchetState::deserialize_message(&[0xff, 0xff]),
            Err(CryptoError::MalformedMessage)
        ));

        let _: RatchetMessage =
            serialization::deserialize(&encoded).expect("format is postcard-compatible");
    }

    #[test]
    fn rejects_unsupported_message_version() {
        let (mut alice, mut bob) = established_pair();
        let mut message = alice.encrypt(b"version", b"").expect("encrypt");
        message.header.version = 9;

        assert!(matches!(
            bob.decrypt(&message, b""),
            Err(CryptoError::InvalidProtocolVersion { received: 9 })
        ));
    }

    #[test]
    fn state_debug_redacts_secret_values() {
        let (alice, _) = established_pair();
        let debug = format!("{alice:?}");
        assert!(!debug.contains("root_key: SecretBytes("));
        assert!(!debug.contains("local_ratchet_key: SecretKey {"));
        assert!(debug.contains("[REDACTED]"));
    }

    #[test]
    fn protected_state_export_restores_conversation_progress() {
        let (mut alice, bob) = established_pair();
        let message = alice.encrypt(b"before restart", b"").expect("encrypt");
        let storage_key = [0x71; 32];
        let snapshot = bob
            .export_state(&storage_key)
            .expect("export encrypted state");
        let mut restored =
            DoubleRatchetState::import_state(&snapshot, &storage_key).expect("restore state");

        assert_eq!(
            restored
                .decrypt(&message, b"")
                .expect("decrypt after restore")
                .as_slice(),
            b"before restart"
        );
        let reply = restored
            .encrypt(b"after restart", b"")
            .expect("encrypt after restore");
        assert_eq!(
            alice
                .decrypt(&reply, b"")
                .expect("decrypt reply")
                .as_slice(),
            b"after restart"
        );
    }

    #[test]
    fn encrypted_snapshot_rejects_wrong_key_and_modified_ciphertext_or_nonce() {
        let (_, state) = established_pair();
        let storage_key = [0x72; 32];
        let snapshot = state
            .export_state(&storage_key)
            .expect("export encrypted state");
        let second_snapshot = state
            .export_state(&storage_key)
            .expect("export second encrypted state");
        assert_ne!(
            &snapshot[1..13],
            &second_snapshot[1..13],
            "each snapshot must use a fresh nonce"
        );

        assert!(matches!(
            DoubleRatchetState::import_state(&snapshot, &[0x73; 32]),
            Err(CryptoError::AuthenticationFailed)
        ));

        let mut modified_ciphertext = snapshot.clone();
        let ciphertext_index = modified_ciphertext.len() - 1;
        modified_ciphertext[ciphertext_index] ^= 1;
        assert!(matches!(
            DoubleRatchetState::import_state(&modified_ciphertext, &storage_key),
            Err(CryptoError::AuthenticationFailed)
        ));

        let mut modified_nonce = snapshot;
        modified_nonce[1] ^= 1;
        assert!(matches!(
            DoubleRatchetState::import_state(&modified_nonce, &storage_key),
            Err(CryptoError::AuthenticationFailed)
        ));
    }

    #[test]
    fn encrypted_snapshot_rejects_malformed_and_unsupported_versions() {
        let (_, state) = established_pair();
        let storage_key = [0x74; 32];
        let snapshot = state
            .export_state(&storage_key)
            .expect("export encrypted state");

        assert!(matches!(
            DoubleRatchetState::import_state(&snapshot[..snapshot.len() / 2], &storage_key),
            Err(CryptoError::MalformedMessage)
        ));

        let malformed_plaintext = aead::encrypt(
            &AeadKey::from_bytes(storage_key),
            b"not a serialized ratchet state",
            STATE_SNAPSHOT_AAD,
        )
        .expect("encrypt malformed test state");
        let malformed_envelope = serialization::serialize(&EncryptedRatchetState {
            version: ENCRYPTED_STATE_VERSION,
            ciphertext: malformed_plaintext,
        })
        .expect("encode malformed test envelope");
        assert!(matches!(
            DoubleRatchetState::import_state(&malformed_envelope, &storage_key),
            Err(CryptoError::MalformedMessage)
        ));

        let mut wrong_version = snapshot;
        wrong_version[0] = ENCRYPTED_STATE_VERSION + 1;
        assert!(matches!(
            DoubleRatchetState::import_state(&wrong_version, &storage_key),
            Err(CryptoError::InvalidProtocolVersion { received: 2 })
        ));
    }

    #[test]
    fn encrypted_snapshot_rejects_authenticated_unsupported_inner_state_version() {
        let (_, state) = established_pair();
        let storage_key = [0x75; 32];
        let mut snapshot = state.export_state(&storage_key).expect("export");
        let mut encrypted: EncryptedRatchetState =
            serialization::deserialize(&snapshot).expect("decode outer envelope");
        let mut plaintext = aead::decrypt(
            &AeadKey::from_bytes(storage_key),
            &encrypted.ciphertext,
            STATE_SNAPSHOT_AAD,
        )
        .expect("decrypt snapshot");
        plaintext.as_mut_slice()[0] = STATE_VERSION + 1;
        encrypted.ciphertext = aead::encrypt(
            &AeadKey::from_bytes(storage_key),
            plaintext.as_slice(),
            STATE_SNAPSHOT_AAD,
        )
        .expect("encrypt modified test snapshot");
        snapshot = serialization::serialize(&encrypted).expect("encode outer envelope");

        assert!(matches!(
            DoubleRatchetState::import_state(&snapshot, &storage_key),
            Err(CryptoError::InvalidProtocolVersion { received: 3 })
        ));
    }
}
