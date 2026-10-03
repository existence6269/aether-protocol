#[derive(Debug, Eq, PartialEq)]
pub enum CryptoError {
    AuthenticationFailed,
    EncryptionFailed,
    InvalidIdentityKey,
    InvalidSignature,
    IdentityMismatch,
    InvalidKeyLength { expected: usize },
    KeyDerivationOutputTooLong,
    InvalidProtocolVersion { received: u8 },
    InvalidHandshakeState,
    HandshakeReplayDetected,
    MalformedMessage,
    MessageTooLarge,
    MessageCounterExhausted,
    SkippedMessageKeyLimitExceeded { limit: usize },
    RatchetGenerationLimitExceeded { limit: usize },
    ReplayOrExpiredMessage,
    NonContributoryPublicKey,
    NoiseHandshakeFailed,
    ReplayStoreFailed,
    ReplayStoreCapacityExceeded,
    RandomGenerationFailed,
}

impl core::fmt::Display for CryptoError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::AuthenticationFailed => formatter.write_str("authentication failed"),
            Self::EncryptionFailed => formatter.write_str("encryption failed"),
            Self::InvalidIdentityKey => formatter.write_str("invalid Ed25519 identity public key"),
            Self::InvalidSignature => formatter.write_str("signature verification failed"),
            Self::IdentityMismatch => {
                formatter.write_str("peer identity did not match expectation")
            }
            Self::InvalidKeyLength { expected } => {
                write!(formatter, "invalid key length; expected {expected} bytes")
            }
            Self::KeyDerivationOutputTooLong => {
                formatter.write_str("requested HKDF output is too long")
            }
            Self::InvalidProtocolVersion { received } => {
                write!(formatter, "unsupported protocol version {received}")
            }
            Self::InvalidHandshakeState => formatter.write_str("invalid handshake state"),
            Self::HandshakeReplayDetected => {
                formatter.write_str("handshake first flight was already recorded")
            }
            Self::MalformedMessage => formatter.write_str("malformed protocol message"),
            Self::MessageTooLarge => formatter.write_str("protocol message exceeds size limit"),
            Self::MessageCounterExhausted => formatter.write_str("message counter exhausted"),
            Self::SkippedMessageKeyLimitExceeded { limit } => {
                write!(formatter, "skipped message key limit exceeded ({limit})")
            }
            Self::RatchetGenerationLimitExceeded { limit } => {
                write!(
                    formatter,
                    "retired ratchet generation limit exceeded ({limit})"
                )
            }
            Self::ReplayOrExpiredMessage => {
                formatter.write_str("message was replayed or its key has expired")
            }
            Self::NonContributoryPublicKey => {
                formatter.write_str("peer public key does not contribute to the shared secret")
            }
            Self::NoiseHandshakeFailed => formatter.write_str("Noise handshake failed"),
            Self::ReplayStoreFailed => {
                formatter.write_str("handshake replay store could not record the first flight")
            }
            Self::ReplayStoreCapacityExceeded => {
                formatter.write_str("handshake replay store capacity exceeded")
            }
            Self::RandomGenerationFailed => {
                formatter.write_str("secure random number generation failed")
            }
        }
    }
}

impl std::error::Error for CryptoError {}
