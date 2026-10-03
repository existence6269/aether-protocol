use rand_core::{OsRng, RngCore};
use zeroize::Zeroize;

use crate::error::CryptoError;

pub(crate) fn random_array<const N: usize>() -> Result<[u8; N], CryptoError> {
    let mut bytes = [0; N];
    if OsRng.try_fill_bytes(&mut bytes).is_err() {
        bytes.zeroize();
        return Err(CryptoError::RandomGenerationFailed);
    }
    Ok(bytes)
}
