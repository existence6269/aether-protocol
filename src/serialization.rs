use serde::{de::DeserializeOwned, Serialize};

pub fn serialize<T: Serialize>(value: &T) -> Result<Vec<u8>, postcard::Error> {
    postcard::to_allocvec(value)
}

pub fn deserialize<T: DeserializeOwned>(encoded: &[u8]) -> Result<T, postcard::Error> {
    postcard::from_bytes(encoded)
}

#[cfg(test)]
mod tests {
    use crate::identity::PublicKey;

    #[test]
    fn public_key_round_trips_through_postcard() {
        let key = PublicKey::from_bytes([7; 32]);
        let encoded = super::serialize(&key).expect("serialize public key");
        let decoded: PublicKey = super::deserialize(&encoded).expect("deserialize public key");

        assert_eq!(decoded, key);
    }
}
