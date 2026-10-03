use std::collections::HashSet;
use std::sync::Mutex;

use crate::CryptoError;

const DEFAULT_VOLATILE_CAPACITY: usize = 20_000;
const MAX_VOLATILE_CAPACITY: usize = 100_000;

/// Opaque digest identifying one canonical first handshake flight in the
/// context of a responder identity.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct HandshakeReplayId([u8; 32]);

impl HandshakeReplayId {
    pub(crate) const fn from_digest(digest: [u8; 32]) -> Self {
        Self(digest)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl core::fmt::Debug for HandshakeReplayId {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("HandshakeReplayId([REDACTED])")
    }
}

/// Outcome of an atomic first-flight replay-store operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplayDecision {
    Inserted,
    AlreadyPresent,
}

/// Caller-owned atomic replay storage for first handshake flights.
///
/// Implementations backed by durable storage must commit a unique insert before
/// returning `Inserted`. Do not use timestamps alone as replay protection.
/// Return `CryptoError::ReplayStoreFailed` if storage cannot safely decide.
pub trait HandshakeReplayStore: Send + Sync {
    fn check_and_record(&self, replay_id: HandshakeReplayId)
        -> Result<ReplayDecision, CryptoError>;
}

/// Process-local replay store. It rejects concurrent duplicate flights but its
/// history is lost when the value or process is dropped; use a durable
/// `HandshakeReplayStore` implementation when replay protection must survive
/// restarts.
pub struct VolatileHandshakeReplayStore {
    max_entries: usize,
    seen: Mutex<HashSet<HandshakeReplayId>>,
}

impl VolatileHandshakeReplayStore {
    pub fn new(max_entries: usize) -> Result<Self, CryptoError> {
        if max_entries == 0 || max_entries > MAX_VOLATILE_CAPACITY {
            return Err(CryptoError::ReplayStoreCapacityExceeded);
        }

        Ok(Self {
            max_entries,
            seen: Mutex::new(HashSet::new()),
        })
    }
}

impl Default for VolatileHandshakeReplayStore {
    fn default() -> Self {
        Self {
            max_entries: DEFAULT_VOLATILE_CAPACITY,
            seen: Mutex::new(HashSet::new()),
        }
    }
}

impl HandshakeReplayStore for VolatileHandshakeReplayStore {
    fn check_and_record(
        &self,
        replay_id: HandshakeReplayId,
    ) -> Result<ReplayDecision, CryptoError> {
        let mut seen = self
            .seen
            .lock()
            .map_err(|_| CryptoError::ReplayStoreFailed)?;
        if seen.contains(&replay_id) {
            return Ok(ReplayDecision::AlreadyPresent);
        }
        if seen.len() >= self.max_entries {
            return Err(CryptoError::ReplayStoreCapacityExceeded);
        }

        seen.insert(replay_id);
        Ok(ReplayDecision::Inserted)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Barrier};

    use super::{
        HandshakeReplayId, HandshakeReplayStore, ReplayDecision, VolatileHandshakeReplayStore,
    };
    use crate::CryptoError;

    #[test]
    fn records_once_and_fails_closed_at_capacity() {
        let store = VolatileHandshakeReplayStore::new(1).expect("valid capacity");
        let first = HandshakeReplayId::from_digest([1; 32]);
        let second = HandshakeReplayId::from_digest([2; 32]);

        assert_eq!(
            store.check_and_record(first).expect("insert first"),
            ReplayDecision::Inserted
        );
        assert_eq!(
            store.check_and_record(first).expect("detect duplicate"),
            ReplayDecision::AlreadyPresent
        );
        assert!(matches!(
            store.check_and_record(second),
            Err(CryptoError::ReplayStoreCapacityExceeded)
        ));
    }

    #[test]
    fn concurrent_identical_flights_have_exactly_one_winner() {
        let store = Arc::new(VolatileHandshakeReplayStore::default());
        let barrier = Arc::new(Barrier::new(2));
        let replay_id = HandshakeReplayId::from_digest([3; 32]);

        let handles: Vec<_> = (0..2)
            .map(|_| {
                let store = Arc::clone(&store);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    store.check_and_record(replay_id)
                })
            })
            .collect();

        let decisions: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().expect("thread should complete"))
            .collect();
        assert_eq!(
            decisions
                .iter()
                .filter(|decision| matches!(decision, Ok(ReplayDecision::Inserted)))
                .count(),
            1
        );
        assert_eq!(
            decisions
                .iter()
                .filter(|decision| matches!(decision, Ok(ReplayDecision::AlreadyPresent)))
                .count(),
            1
        );
    }
}
