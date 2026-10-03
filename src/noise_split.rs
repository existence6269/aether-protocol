use zeroize::Zeroizing;

use crate::{error::CryptoError, kdf::derive_key, SecretBytes};

const NOISE_HASH_LENGTH: usize = 32;
const NOISE_SPLIT_LENGTH: usize = 32;
const RATCHET_ROOT_LABEL: &[u8] = b"aether/double-ratchet/root/noise-xx/v1";

/// Converts Noise Split output into Aether ratchet root material without
/// exposing the raw directional keys outside this private boundary.
pub(crate) fn derive_ratchet_root(
    handshake: &mut snow::HandshakeState,
) -> Result<SecretBytes, CryptoError> {
    if !handshake.is_handshake_finished() {
        return Err(CryptoError::InvalidHandshakeState);
    }

    let handshake_hash = handshake.get_handshake_hash();
    if handshake_hash.len() != NOISE_HASH_LENGTH {
        return Err(CryptoError::NoiseHandshakeFailed);
    }
    let mut salt = [0u8; NOISE_HASH_LENGTH];
    salt.copy_from_slice(handshake_hash);

    let (first_split, second_split) = handshake.dangerously_get_raw_split();
    let first_split = Zeroizing::new(first_split);
    let second_split = Zeroizing::new(second_split);
    let mut split_material = Zeroizing::new([0u8; NOISE_SPLIT_LENGTH * 2]);
    split_material[..NOISE_SPLIT_LENGTH].copy_from_slice(&first_split[..]);
    split_material[NOISE_SPLIT_LENGTH..].copy_from_slice(&second_split[..]);

    derive_key(
        Some(&salt),
        &split_material[..],
        RATCHET_ROOT_LABEL,
        NOISE_HASH_LENGTH,
    )
}

#[cfg(test)]
mod tests {
    use snow::{params::NoiseParams, Builder};

    use crate::{noise_split::derive_ratchet_root, CryptoError};

    const PROFILE: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";

    fn handshake_state(initiator: bool, key: &[u8; 32]) -> snow::HandshakeState {
        let params = PROFILE.parse::<NoiseParams>().expect("known Noise profile");
        let prologue = b"aether/noise-test/v1";
        let builder = Builder::new(params)
            .prologue(prologue)
            .expect("valid test prologue")
            .local_private_key(key)
            .expect("valid test private key");

        if initiator {
            builder.build_initiator().expect("build test initiator")
        } else {
            builder.build_responder().expect("build test responder")
        }
    }

    fn exchange(sender: &mut snow::HandshakeState, receiver: &mut snow::HandshakeState) {
        let mut message = [0u8; 1024];
        let mut payload = [0u8; 1024];
        let written = sender
            .write_message(b"", &mut message)
            .expect("write Noise handshake message");
        receiver
            .read_message(&message[..written], &mut payload)
            .expect("read Noise handshake message");
    }

    #[test]
    fn both_roles_derive_the_same_split_separated_ratchet_root() {
        let mut initiator = handshake_state(true, &[0x31; 32]);
        let mut responder = handshake_state(false, &[0x42; 32]);

        exchange(&mut initiator, &mut responder);
        exchange(&mut responder, &mut initiator);
        exchange(&mut initiator, &mut responder);

        let initiator_root =
            derive_ratchet_root(&mut initiator).expect("completed initiator split");
        let responder_root =
            derive_ratchet_root(&mut responder).expect("completed responder split");

        assert_eq!(initiator_root.as_slice(), responder_root.as_slice());
        assert_eq!(
            initiator.get_handshake_hash(),
            responder.get_handshake_hash()
        );

        let mut initiator_transport = initiator
            .into_transport_mode()
            .expect("completed initiator enters Noise transport mode");
        let mut responder_transport = responder
            .into_transport_mode()
            .expect("completed responder enters Noise transport mode");
        let mut ciphertext = [0u8; 128];
        let ciphertext_length = initiator_transport
            .write_message(b"Noise XX transport check", &mut ciphertext)
            .expect("encrypt Noise transport test");
        let mut plaintext = [0u8; 128];
        let plaintext_length = responder_transport
            .read_message(&ciphertext[..ciphertext_length], &mut plaintext)
            .expect("decrypt Noise transport test");

        assert_eq!(&plaintext[..plaintext_length], b"Noise XX transport check");
    }

    #[test]
    fn refuses_split_access_before_noise_handshake_completion() {
        let mut initiator = handshake_state(true, &[0x51; 32]);

        assert!(matches!(
            derive_ratchet_root(&mut initiator),
            Err(CryptoError::InvalidHandshakeState)
        ));
    }
}
