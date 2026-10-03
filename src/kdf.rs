use hkdf::Hkdf;
use sha2::Sha256;

use crate::{error::CryptoError, SecretBytes};

pub fn derive_key(
    salt: Option<&[u8]>,
    input_key_material: &[u8],
    info: &[u8],
    output_length: usize,
) -> Result<SecretBytes, CryptoError> {
    if output_length > 255 * 32 {
        return Err(CryptoError::KeyDerivationOutputTooLong);
    }

    let hkdf = Hkdf::<Sha256>::new(salt, input_key_material);
    let mut output = SecretBytes::from_vec(vec![0; output_length]);
    hkdf.expand(info, output.as_mut_slice())
        .map_err(|_| CryptoError::KeyDerivationOutputTooLong)?;

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::derive_key;
    use crate::CryptoError;

    #[test]
    fn derivation_is_deterministic_for_the_same_inputs() {
        let first = derive_key(Some(b"salt"), b"input key material", b"context", 32)
            .expect("valid output length");
        let second = derive_key(Some(b"salt"), b"input key material", b"context", 32)
            .expect("valid output length");

        assert_eq!(first.as_slice(), second.as_slice());
    }

    #[test]
    fn matches_rfc_5869_sha256_test_case_one() {
        let input_key_material = [0x0b; 22];
        let salt = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ];
        let info = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];
        let expected = [
            0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36,
            0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56,
            0xec, 0xc4, 0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65,
        ];
        let derived = derive_key(Some(&salt), &input_key_material, &info, expected.len())
            .expect("RFC test vector has a valid output length");

        assert_eq!(derived.as_slice(), expected);
    }

    #[test]
    fn derivation_changes_with_context() {
        let first =
            derive_key(None, b"input key material", b"context-a", 32).expect("valid output length");
        let second =
            derive_key(None, b"input key material", b"context-b", 32).expect("valid output length");

        assert_ne!(first.as_slice(), second.as_slice());
    }

    #[test]
    fn rejects_output_longer_than_hkdf_limit() {
        assert!(matches!(
            derive_key(None, b"input", b"context", 255 * 32 + 1),
            Err(CryptoError::KeyDerivationOutputTooLong)
        ));
    }
}
