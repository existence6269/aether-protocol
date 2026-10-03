use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use serde::{de::Error as DeError, Deserialize, Deserializer, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{error::CryptoError, random::random_array, SecretBytes};

const KEY_LENGTH: usize = 32;
const NONCE_LENGTH: usize = 12;
const MAX_CIPHERTEXT_BYTES: usize = 2 * 1024 * 1024 + 16;

/// A 256-bit AES-GCM key that is zeroized when dropped.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct AeadKey {
    bytes: [u8; KEY_LENGTH],
}

impl AeadKey {
    #[cfg(test)]
    pub fn generate() -> Result<Self, CryptoError> {
        Ok(Self {
            bytes: random_array()?,
        })
    }

    pub fn from_bytes(mut bytes: [u8; KEY_LENGTH]) -> Self {
        let key = Self { bytes };
        bytes.zeroize();
        key
    }

    pub(crate) fn duplicate(&self) -> Self {
        Self { bytes: self.bytes }
    }

    pub(crate) fn export_bytes(&self) -> [u8; KEY_LENGTH] {
        self.bytes
    }
}

impl core::fmt::Debug for AeadKey {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("AeadKey([REDACTED])")
    }
}

/// An authenticated encrypted payload, including its randomly generated nonce.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AeadCiphertext {
    nonce: [u8; NONCE_LENGTH],
    ciphertext: Vec<u8>,
}

impl<'de> Deserialize<'de> for AeadCiphertext {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct WireCiphertext {
            nonce: [u8; NONCE_LENGTH],
            #[serde(deserialize_with = "deserialize_ciphertext_bytes")]
            ciphertext: Vec<u8>,
        }

        let wire = WireCiphertext::deserialize(deserializer)?;
        Ok(Self {
            nonce: wire.nonce,
            ciphertext: wire.ciphertext,
        })
    }
}

fn deserialize_ciphertext_bytes<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<u8>, D::Error> {
    struct CiphertextBytesVisitor;

    impl<'de> serde::de::Visitor<'de> for CiphertextBytesVisitor {
        type Value = Vec<u8>;

        fn expecting(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            formatter.write_str("ciphertext bytes up to 2 MiB plus authentication tag")
        }

        fn visit_seq<A: serde::de::SeqAccess<'de>>(
            self,
            mut sequence: A,
        ) -> Result<Self::Value, A::Error> {
            let mut bytes = Vec::new();
            while let Some(byte) = sequence.next_element()? {
                if bytes.len() == MAX_CIPHERTEXT_BYTES {
                    return Err(A::Error::custom("AEAD ciphertext exceeds size limit"));
                }
                bytes.push(byte);
            }
            Ok(bytes)
        }
    }

    deserializer.deserialize_seq(CiphertextBytesVisitor)
}

impl AeadCiphertext {
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    #[cfg(test)]
    pub(crate) fn corrupt_first_ciphertext_byte(&mut self) {
        if let Some(byte) = self.ciphertext.first_mut() {
            *byte ^= 1;
        }
    }
}

pub fn encrypt(
    key: &AeadKey,
    plaintext: &[u8],
    associated_data: &[u8],
) -> Result<AeadCiphertext, CryptoError> {
    let nonce = random_array()?;
    let cipher =
        Aes256Gcm::new_from_slice(&key.bytes).map_err(|_| CryptoError::InvalidKeyLength {
            expected: KEY_LENGTH,
        })?;
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: associated_data,
            },
        )
        .map_err(|_| CryptoError::EncryptionFailed)?;

    Ok(AeadCiphertext { nonce, ciphertext })
}

pub fn decrypt(
    key: &AeadKey,
    encrypted: &AeadCiphertext,
    associated_data: &[u8],
) -> Result<SecretBytes, CryptoError> {
    let cipher =
        Aes256Gcm::new_from_slice(&key.bytes).map_err(|_| CryptoError::InvalidKeyLength {
            expected: KEY_LENGTH,
        })?;
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&encrypted.nonce),
            Payload {
                msg: &encrypted.ciphertext,
                aad: associated_data,
            },
        )
        .map_err(|_| CryptoError::AuthenticationFailed)?;

    Ok(SecretBytes::from_vec(plaintext))
}

#[cfg(test)]
mod tests {
    use super::{decrypt, encrypt, AeadCiphertext, AeadKey};
    use crate::CryptoError;

    #[test]
    fn encrypts_and_decrypts_successfully() {
        let key = AeadKey::generate().expect("secure randomness should be available");
        let encrypted = encrypt(&key, b"message", b"header").expect("encryption should succeed");
        let plaintext = decrypt(&key, &encrypted, b"header").expect("decryption should succeed");

        assert_eq!(plaintext.as_slice(), b"message");
    }

    #[test]
    fn rejects_wrong_key() {
        let key = AeadKey::generate().expect("secure randomness should be available");
        let wrong_key = AeadKey::generate().expect("secure randomness should be available");
        let encrypted = encrypt(&key, b"message", b"").expect("encryption should succeed");

        assert!(matches!(
            decrypt(&wrong_key, &encrypted, b""),
            Err(CryptoError::AuthenticationFailed)
        ));
    }

    #[test]
    fn rejects_modified_ciphertext() {
        let key = AeadKey::generate().expect("secure randomness should be available");
        let mut encrypted = encrypt(&key, b"message", b"").expect("encryption should succeed");
        encrypted.ciphertext[0] ^= 1;

        assert!(matches!(
            decrypt(&key, &encrypted, b""),
            Err(CryptoError::AuthenticationFailed)
        ));
    }

    #[test]
    fn rejects_modified_associated_data() {
        let key = AeadKey::generate().expect("secure randomness should be available");
        let encrypted = encrypt(&key, b"message", b"header").expect("encryption should succeed");

        assert!(matches!(
            decrypt(&key, &encrypted, b"other header"),
            Err(CryptoError::AuthenticationFailed)
        ));
    }

    #[test]
    fn ciphertext_round_trips_through_postcard() {
        let key = AeadKey::generate().expect("secure randomness should be available");
        let encrypted = encrypt(&key, b"message", b"").expect("encryption should succeed");
        let encoded = crate::serialization::serialize(&encrypted).expect("serialize ciphertext");
        let decoded: AeadCiphertext =
            crate::serialization::deserialize(&encoded).expect("deserialize ciphertext");

        assert_eq!(decoded, encrypted);
        assert_eq!(
            decrypt(&key, &decoded, b"")
                .expect("decryption should succeed")
                .as_slice(),
            b"message"
        );
    }
}
