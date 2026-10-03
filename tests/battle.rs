use std::collections::HashSet;

use aether_crypto::{
    CryptoError, Handshake, HandshakeFinish, Identity, Message, Session,
    VolatileHandshakeReplayStore,
};

const SEED_MASSIVE: u64 = 0xA37E_2026_1001;
const SEED_GENERATIONS: u64 = 0xA37E_2026_1002;
const SEED_PERSISTENCE: u64 = 0xA37E_2026_1003;
const SEED_MUTATIONS: u64 = 0xA37E_2026_1004;
const SEED_TRANSPORT: u64 = 0xA37E_2026_1005;
const SEED_HANDSHAKE: u64 = 0xA37E_2026_1006;
const ALICE_STORAGE_KEY: [u8; 32] = [0xA1; 32];
const BOB_STORAGE_KEY: [u8; 32] = [0xB2; 32];

struct TestRng(u64);

impl TestRng {
    fn new(seed: u64) -> Self {
        Self(seed)
    }

    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut value = self.0;
        value = (value ^ (value >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        value ^ (value >> 31)
    }

    fn range(&mut self, upper_exclusive: usize) -> usize {
        if upper_exclusive == 0 {
            0
        } else {
            (self.next_u64() as usize) % upper_exclusive
        }
    }

    fn chance(&mut self, numerator: u32, denominator: u32) -> bool {
        (self.next_u64() % denominator as u64) < numerator as u64
    }

    fn bytes(&mut self, length: usize) -> Vec<u8> {
        (0..length).map(|_| self.next_u64() as u8).collect()
    }

    fn shuffle<T>(&mut self, values: &mut [T]) {
        for index in (1..values.len()).rev() {
            values.swap(index, self.range(index + 1));
        }
    }
}

struct Pair {
    alice: Session,
    bob: Session,
}

impl Pair {
    fn new() -> Self {
        let alice = Identity::from_secret_bytes(&[0x31; 32]).expect("fixed valid Alice seed");
        let bob = Identity::from_secret_bytes(&[0x42; 32]).expect("fixed valid Bob seed");
        let replay_store = VolatileHandshakeReplayStore::default();
        let (alice_pending, init) = alice
            .initiate_handshake(bob.public_key())
            .expect("initiate handshake");
        let init = wire_handshake(init);
        let (bob_pending, response) = bob
            .respond_to_handshake(alice.public_key(), init, &replay_store)
            .expect("respond to handshake");
        let response = wire_handshake(response);
        let (finish, alice_session) = alice_pending
            .process_response(&alice, response)
            .expect("process responder flight");
        let finish = wire_handshake(finish);
        let bob_session = bob_pending.complete(finish).expect("complete handshake");
        Self {
            alice: alice_session,
            bob: bob_session,
        }
    }

    fn export_both(&self) -> (Vec<u8>, Vec<u8>) {
        (
            self.alice
                .export_state(&ALICE_STORAGE_KEY)
                .expect("export Alice"),
            self.bob.export_state(&BOB_STORAGE_KEY).expect("export Bob"),
        )
    }

    fn restore_both(&mut self) {
        let (alice, bob) = self.export_both();
        self.alice = Session::import_state(&alice, &ALICE_STORAGE_KEY).expect("restore Alice");
        self.bob = Session::import_state(&bob, &BOB_STORAGE_KEY).expect("restore Bob");
    }

    fn fork(&self) -> Self {
        let (alice, bob) = self.export_both();
        Self {
            alice: Session::import_state(&alice, &ALICE_STORAGE_KEY).expect("fork Alice"),
            bob: Session::import_state(&bob, &BOB_STORAGE_KEY).expect("fork Bob"),
        }
    }

    fn send(&mut self, from_alice: bool, plaintext: &[u8], aad: &[u8]) -> Message {
        if from_alice {
            self.alice.encrypt(plaintext, aad).expect("Alice encrypt")
        } else {
            self.bob.encrypt(plaintext, aad).expect("Bob encrypt")
        }
    }

    fn deliver(
        &mut self,
        from_alice: bool,
        message: &Message,
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        if from_alice {
            self.bob
                .decrypt(message, aad)
                .map(|decrypted| decrypted.as_slice().to_vec())
        } else {
            self.alice
                .decrypt(message, aad)
                .map(|decrypted| decrypted.as_slice().to_vec())
        }
        .map(|decrypted| {
            assert_eq!(decrypted, plaintext);
            decrypted
        })
    }
}

fn wire_handshake(message: Handshake) -> Handshake {
    let encoded = message
        .to_bytes()
        .expect("serialize public handshake flight");
    Handshake::from_bytes(&encoded).expect("parse public handshake flight")
}

fn assert_seed(condition: bool, seed: u64, context: &str) {
    assert!(condition, "{context}; reproducible test seed: {seed:#018x}");
}

#[derive(Clone)]
struct Packet {
    id: u64,
    from_alice: bool,
    message: Message,
    plaintext: Vec<u8>,
    aad: Vec<u8>,
}

fn deliver_packet(pair: &mut Pair, packet: &Packet, seed: u64) {
    match pair.deliver(
        packet.from_alice,
        &packet.message,
        &packet.plaintext,
        &packet.aad,
    ) {
        Ok(_) => {}
        Err(error) => panic!(
            "valid packet {} failed delivery: {error:?}; seed {seed:#018x}",
            packet.id
        ),
    }
}

#[test]
fn massive_seeded_randomized_conversation() {
    let seed = SEED_MASSIVE;
    let mut rng = TestRng::new(seed);
    let mut pair = Pair::new();
    let mut queue: Vec<Packet> = Vec::new();
    let mut accepted = HashSet::new();
    let mut sent = 0u64;
    let mut dropped = 0usize;
    let mut duplicates = 0usize;

    while sent < 10_000 {
        let batch_size = ((10_000 - sent) as usize).min(1 + rng.range(24));
        for _ in 0..batch_size {
            let id = sent;
            sent += 1;
            let from_alice = rng.chance(1, 2);
            let plaintext_length = rng.range(769);
            let plaintext = rng.bytes(plaintext_length);
            let aad = [b"massive/".as_slice(), &id.to_le_bytes()].concat();
            let message = pair.send(from_alice, &plaintext, &aad);
            let packet = Packet {
                id,
                from_alice,
                message,
                plaintext,
                aad,
            };

            if rng.chance(1, 12) {
                dropped += 1;
                continue;
            }
            if rng.chance(1, 10) {
                queue.push(packet.clone());
                duplicates += 1;
            }
            queue.push(packet);
        }

        rng.shuffle(&mut queue);
        while !queue.is_empty() {
            let packet = queue.swap_remove(rng.range(queue.len()));
            if accepted.contains(&packet.id) {
                let error = if packet.from_alice {
                    pair.bob.decrypt(&packet.message, &packet.aad)
                } else {
                    pair.alice.decrypt(&packet.message, &packet.aad)
                };
                assert!(
                    matches!(error, Err(CryptoError::ReplayOrExpiredMessage)),
                    "duplicate {} should be rejected as replay, got {error:?}; seed {seed:#018x}",
                    packet.id
                );
                continue;
            }

            deliver_packet(&mut pair, &packet, seed);
            assert_seed(
                accepted.insert(packet.id),
                seed,
                "a unique packet was accepted more than once",
            );
            if rng.chance(1, 20) {
                let replay = if packet.from_alice {
                    pair.bob.decrypt(&packet.message, &packet.aad)
                } else {
                    pair.alice.decrypt(&packet.message, &packet.aad)
                };
                assert!(
                    matches!(replay, Err(CryptoError::ReplayOrExpiredMessage)),
                    "post-delivery replay should be rejected; seed {seed:#018x}"
                );
                duplicates += 1;
            }
        }
    }

    for index in 0..32 {
        let from_alice = index % 2 == 0;
        let body = format!("conversation remains live {index}");
        let message = pair.send(from_alice, body.as_bytes(), b"tail");
        deliver_packet(
            &mut pair,
            &Packet {
                id: sent + index,
                from_alice,
                message,
                plaintext: body.into_bytes(),
                aad: b"tail".to_vec(),
            },
            seed,
        );
    }

    assert_seed(sent == 10_000, seed, "message target mismatch");
    assert_seed(
        accepted.len() + dropped >= sent as usize,
        seed,
        "accounting mismatch",
    );
    assert_seed(
        duplicates > 0,
        seed,
        "no duplicate/replay operations occurred",
    );
    assert_seed(dropped > 0, seed, "no messages were dropped");
    assert_seed(
        pair.alice.skipped_message_key_count() <= 2_000
            && pair.bob.skipped_message_key_count() <= 2_000,
        seed,
        "skipped-key limit invariant failed",
    );
}

#[test]
fn delayed_messages_survive_many_dh_ratchet_generations() {
    const GENERATIONS: usize = 64;
    const MESSAGES_PER_CHAIN: usize = 8;
    let seed = SEED_GENERATIONS;
    let mut rng = TestRng::new(seed);
    let mut pair = Pair::new();
    let mut delayed: Vec<Packet> = Vec::new();
    let mut id = 0u64;

    for generation in 0..GENERATIONS {
        let mut alice_chain = Vec::new();
        for number in 0..MESSAGES_PER_CHAIN {
            let body = format!("A generation {generation} message {number}");
            let message = pair.send(true, body.as_bytes(), b"generations");
            alice_chain.push(Packet {
                id,
                from_alice: true,
                message,
                plaintext: body.into_bytes(),
                aad: b"generations".to_vec(),
            });
            id += 1;
        }
        deliver_packet(&mut pair, alice_chain.last().expect("nonempty chain"), seed);
        delayed.extend(alice_chain.into_iter().take(MESSAGES_PER_CHAIN - 1));

        let mut bob_chain = Vec::new();
        for number in 0..MESSAGES_PER_CHAIN {
            let body = format!("B generation {generation} message {number}");
            let message = pair.send(false, body.as_bytes(), b"generations");
            bob_chain.push(Packet {
                id,
                from_alice: false,
                message,
                plaintext: body.into_bytes(),
                aad: b"generations".to_vec(),
            });
            id += 1;
        }
        deliver_packet(&mut pair, bob_chain.last().expect("nonempty chain"), seed);
        delayed.extend(bob_chain.into_iter().take(MESSAGES_PER_CHAIN - 1));

        assert_seed(
            pair.alice.skipped_message_key_count() + pair.bob.skipped_message_key_count() <= 2_000,
            seed,
            "skipped keys exceeded default bound during generation",
        );
    }

    pair.restore_both();
    rng.shuffle(&mut delayed);
    let mut consumed = Vec::new();
    for packet in &delayed {
        deliver_packet(&mut pair, packet, seed);
        consumed.push(packet.clone());
    }
    for packet in consumed.iter().step_by(19) {
        let replay = if packet.from_alice {
            pair.bob.decrypt(&packet.message, &packet.aad)
        } else {
            pair.alice.decrypt(&packet.message, &packet.aad)
        };
        assert!(
            matches!(replay, Err(CryptoError::ReplayOrExpiredMessage)),
            "replayed skipped message was not rejected; seed {seed:#018x}"
        );
    }

    assert_seed(
        pair.alice.skipped_message_key_count() == 0 && pair.bob.skipped_message_key_count() == 0,
        seed,
        "consumed delayed messages left skipped keys behind",
    );
    pair.restore_both();
    for index in 0..20 {
        let from_alice = index % 2 == 0;
        let body = format!("post-torture {index}");
        let message = pair.send(from_alice, body.as_bytes(), b"continue");
        deliver_packet(
            &mut pair,
            &Packet {
                id: id + index,
                from_alice,
                message,
                plaintext: body.into_bytes(),
                aad: b"continue".to_vec(),
            },
            seed,
        );
    }
}

#[test]
fn randomized_crash_restart_state_persistence() {
    let seed = SEED_PERSISTENCE;
    let mut rng = TestRng::new(seed);
    let mut pair = Pair::new();
    let mut candidate = pair.fork();
    let mut delayed: Vec<(Packet, Packet)> = Vec::new();

    for step in 0..1_200u64 {
        let from_alice = rng.chance(1, 2);
        let body = {
            let mut bytes = step.to_le_bytes().to_vec();
            let random_length = rng.range(192);
            bytes.extend(rng.bytes(random_length));
            bytes
        };
        let message = pair.send(from_alice, &body, b"persist-aad");
        let reference_packet = Packet {
            id: step,
            from_alice,
            message,
            plaintext: body.clone(),
            aad: b"persist-aad".to_vec(),
        };
        let candidate_packet = Packet {
            id: step,
            from_alice,
            message: candidate.send(from_alice, &body, b"persist-aad"),
            plaintext: body,
            aad: b"persist-aad".to_vec(),
        };

        if rng.chance(1, 7) {
            delayed.push((reference_packet, candidate_packet));
        } else {
            deliver_packet(&mut pair, &reference_packet, seed);
            deliver_packet(&mut candidate, &candidate_packet, seed);
        }

        if step % 23 == 0 {
            let (alice_state, bob_state) = pair.export_both();
            let (candidate_alice_state, candidate_bob_state) = candidate.export_both();
            let restored_alice =
                Session::import_state(&alice_state, &ALICE_STORAGE_KEY).expect("restore Alice");
            let restored_bob =
                Session::import_state(&bob_state, &BOB_STORAGE_KEY).expect("restore Bob");
            let restored_candidate_alice =
                Session::import_state(&candidate_alice_state, &ALICE_STORAGE_KEY)
                    .expect("restore candidate Alice");
            let restored_candidate_bob =
                Session::import_state(&candidate_bob_state, &BOB_STORAGE_KEY)
                    .expect("restore candidate Bob");
            candidate.alice = restored_candidate_alice;
            candidate.bob = restored_candidate_bob;
            pair.alice = restored_alice;
            pair.bob = restored_bob;
        }

        if delayed.len() >= 20 {
            rng.shuffle(&mut delayed);
            let (reference_packet, candidate_packet) =
                delayed.pop().expect("at least twenty delayed packets");
            deliver_packet(&mut pair, &reference_packet, seed);
            deliver_packet(&mut candidate, &candidate_packet, seed);
        }
    }

    rng.shuffle(&mut delayed);
    for (reference_packet, candidate_packet) in delayed {
        deliver_packet(&mut pair, &reference_packet, seed);
        deliver_packet(&mut candidate, &candidate_packet, seed);
        let (alice_after, bob_after) = pair.export_both();
        assert!(
            alice_after.len() <= 2 * 1024 * 1024 && bob_after.len() <= 2 * 1024 * 1024,
            "state exceeded documented bound; seed {seed:#018x}"
        );

        assert_eq!(
            pair.alice.skipped_message_key_count(),
            candidate.alice.skipped_message_key_count(),
            "Alice skipped-key state diverged after restore; seed {seed:#018x}"
        );
        assert_eq!(
            pair.bob.skipped_message_key_count(),
            candidate.bob.skipped_message_key_count(),
            "Bob skipped-key state diverged after restore; seed {seed:#018x}"
        );
    }

    for _ in 0..80 {
        pair.restore_both();
        candidate.restore_both();
        let state = pair
            .alice
            .export_state(&ALICE_STORAGE_KEY)
            .expect("export for corruption checks");
        let mut invalid_version = state.clone();
        *invalid_version
            .first_mut()
            .expect("serialized state has version") = 0xff;
        assert!(
            matches!(
                Session::import_state(&invalid_version, &ALICE_STORAGE_KEY),
                Err(CryptoError::InvalidProtocolVersion { received: 0xff })
            ),
            "tampered version should fail import; seed {seed:#018x}"
        );
        assert!(
            matches!(
                Session::import_state(&invalid_version, &ALICE_STORAGE_KEY),
                Err(CryptoError::InvalidProtocolVersion { received: 0xff })
            ),
            "tampered candidate state should fail import; seed {seed:#018x}"
        );

        let truncated = &state[..state.len() / 2];
        assert!(
            matches!(
                Session::import_state(truncated, &ALICE_STORAGE_KEY),
                Err(CryptoError::MalformedMessage)
            ),
            "truncated state should fail import; seed {seed:#018x}"
        );
    }

    let message = pair
        .alice
        .encrypt(b"still alive", b"after-import-failures")
        .expect("send");
    assert_eq!(
        pair.bob
            .decrypt(&message, b"after-import-failures")
            .expect("valid peer session remains usable")
            .as_slice(),
        b"still alive"
    );
    let candidate_message = candidate
        .alice
        .encrypt(b"still alive", b"after-import-failures")
        .expect("candidate send");
    assert_eq!(
        candidate
            .bob
            .decrypt(&candidate_message, b"after-import-failures")
            .expect("candidate peer remains usable")
            .as_slice(),
        b"still alive"
    );
}

#[test]
fn seeded_malicious_wire_input_mutation_harness() {
    let seed = SEED_MUTATIONS;
    let mut rng = TestRng::new(seed);
    let alice = Identity::from_secret_bytes(&[0x51; 32]).expect("valid seed");
    let bob = Identity::from_secret_bytes(&[0x62; 32]).expect("valid seed");

    let mut pair = Pair::new();
    let valid_message = pair.send(true, b"immutable authenticated payload", b"aad");
    let valid_wire = valid_message.to_bytes().expect("encode message");

    let (_pending, valid_init) = alice
        .initiate_handshake(bob.public_key())
        .expect("initiate attack fixture");
    let valid_init_wire = valid_init.to_bytes().expect("encode init");
    let (pending, valid_init) = alice
        .initiate_handshake(bob.public_key())
        .expect("second handshake fixture");
    let replay_store = VolatileHandshakeReplayStore::default();
    let (responder, valid_response) = bob
        .respond_to_handshake(alice.public_key(), valid_init, &replay_store)
        .expect("response fixture");
    let (valid_finish, _) = pending
        .process_response(&alice, valid_response.clone())
        .expect("finish fixture");
    let valid_handshake_wires = [
        valid_init_wire,
        valid_response.to_bytes().expect("encode response"),
        valid_finish.to_bytes().expect("encode finish"),
    ];
    drop(
        responder
            .complete(valid_finish)
            .expect("complete fuzz-fixture handshake"),
    );

    for iteration in 0..5_000 {
        let garbage_length = rng.range(256);
        let mut malformed = rng.bytes(garbage_length);
        match iteration % 8 {
            0 => {
                let wire = &valid_handshake_wires[iteration % valid_handshake_wires.len()];
                if !wire.is_empty() {
                    let end = 1 + rng.range(wire.len());
                    malformed = wire[..end].to_vec();
                }
            }
            1 => {
                malformed = valid_handshake_wires[iteration % valid_handshake_wires.len()].clone();
                let index = rng.range(malformed.len());
                malformed[index] ^= 1 << rng.range(8);
            }
            2 => {
                malformed = valid_wire.clone();
                let index = rng.range(malformed.len());
                malformed[index] ^= 1 << rng.range(8);
            }
            3 => {
                malformed = valid_wire.clone();
                let index = rng.range(malformed.len());
                malformed.insert(index, rng.next_u64() as u8);
            }
            4 => {
                malformed = valid_wire.clone();
                if !malformed.is_empty() {
                    malformed.remove(rng.range(malformed.len()));
                }
            }
            5 => malformed = vec![0xff; 1_048_577],
            6 => malformed = vec![0; 4_097],
            _ => {}
        }

        let handshake_result = Handshake::from_bytes(&malformed);
        let message_result = Message::from_bytes(&malformed);
        let state_result = Session::import_state(&malformed, &ALICE_STORAGE_KEY);
        let _malformed_or_accidentally_valid_input_is_bounded =
            (handshake_result, message_result, state_result);
    }

    for iteration in 0..2_000 {
        let aad_length = rng.range(96);
        let aad = rng.bytes(aad_length);
        let result = pair.bob.decrypt(&valid_message, &aad);
        assert!(
            result.is_err(),
            "wrong external AAD was accepted at iteration {iteration}; seed {seed:#018x}"
        );
    }

    let mut modified_wire = valid_wire.clone();
    for _ in 0..2_000 {
        modified_wire.clone_from(&valid_wire);
        let index = rng.range(modified_wire.len());
        modified_wire[index] ^= 1 << rng.range(8);
        if let Ok(message) = Message::from_bytes(&modified_wire) {
            let result = pair.bob.decrypt(&message, b"aad");
            assert!(
                result.is_err(),
                "authenticated packet mutation was accepted at byte {index}; seed {seed:#018x}"
            );
        }
    }
    assert_eq!(
        pair.bob
            .decrypt(&valid_message, b"aad")
            .expect("failed inputs must not advance state")
            .as_slice(),
        b"immutable authenticated payload"
    );

    for iteration in 0..2_000 {
        let mut mutated_state = pair.alice.export_state(&ALICE_STORAGE_KEY).expect("export");
        if iteration % 4 == 0 {
            mutated_state.truncate(rng.range(mutated_state.len()));
        } else if !mutated_state.is_empty() {
            let index = rng.range(mutated_state.len());
            mutated_state[index] ^= 1 << rng.range(8);
        }
        let _snapshot_authentication_rejects_mutations =
            Session::import_state(&mutated_state, &ALICE_STORAGE_KEY);
    }
}

#[test]
fn unreliable_transport_with_disconnects_and_session_restarts() {
    let seed = SEED_TRANSPORT;
    let mut rng = TestRng::new(seed);
    let mut pair = Pair::new();
    let mut network: Vec<Packet> = Vec::new();
    let mut accepted = HashSet::new();
    let mut next_id = 0u64;
    let mut generated = 0usize;
    let mut replay_attempts = 0usize;

    for tick in 0..3_000 {
        if rng.chance(1, 2) {
            let id = next_id;
            next_id += 1;
            let from_alice = rng.chance(1, 2);
            let mut plaintext = id.to_le_bytes().to_vec();
            let random_length = rng.range(128);
            plaintext.extend(rng.bytes(random_length));
            let message = pair.send(from_alice, &plaintext, b"simulated-link");
            let packet = Packet {
                id,
                from_alice,
                message,
                plaintext,
                aad: b"simulated-link".to_vec(),
            };
            if rng.chance(1, 15) {
                network.push(packet.clone());
            }
            if !rng.chance(1, 12) {
                network.push(packet);
            }
            generated += 1;
        }

        if tick % 37 == 0 {
            pair.restore_both();
        }

        if tick % 211 < 25 {
            continue;
        }

        if !network.is_empty() && rng.chance(3, 4) {
            let packet = network.swap_remove(rng.range(network.len()));
            if rng.chance(1, 10) {
                continue;
            }
            if accepted.contains(&packet.id) {
                let result = if packet.from_alice {
                    pair.bob.decrypt(&packet.message, &packet.aad)
                } else {
                    pair.alice.decrypt(&packet.message, &packet.aad)
                };
                assert!(
                    matches!(result, Err(CryptoError::ReplayOrExpiredMessage)),
                    "transport duplicate not rejected: {result:?}; seed {seed:#018x}"
                );
                replay_attempts += 1;
            } else {
                deliver_packet(&mut pair, &packet, seed);
                accepted.insert(packet.id);
            }
        }
    }

    rng.shuffle(&mut network);
    for packet in network {
        if accepted.contains(&packet.id) {
            continue;
        }
        match pair.deliver(
            packet.from_alice,
            &packet.message,
            &packet.plaintext,
            &packet.aad,
        ) {
            Ok(_) => {
                accepted.insert(packet.id);
            }
            Err(CryptoError::ReplayOrExpiredMessage) => {}
            Err(error) => panic!("transport drain failed: {error:?}; seed {seed:#018x}"),
        }
    }

    assert_seed(generated > 1_000, seed, "transport workload too small");
    assert_seed(!accepted.is_empty(), seed, "transport accepted no messages");
    assert_seed(
        replay_attempts > 0,
        seed,
        "transport generated no replay attempts",
    );

    for index in 0..64 {
        let from_alice = index % 2 == 0;
        let body = format!("reconnected {index}");
        let message = pair.send(from_alice, body.as_bytes(), b"reconnected");
        deliver_packet(
            &mut pair,
            &Packet {
                id: next_id + index,
                from_alice,
                message,
                plaintext: body.into_bytes(),
                aad: b"reconnected".to_vec(),
            },
            seed,
        );
    }
}

#[test]
fn identity_and_handshake_attack_suite() {
    let seed = SEED_HANDSHAKE;
    let alice = Identity::from_secret_bytes(&[0x71; 32]).expect("Alice identity");
    let bob = Identity::from_secret_bytes(&[0x72; 32]).expect("Bob identity");
    let mallory = Identity::from_secret_bytes(&[0x73; 32]).expect("Mallory identity");
    let replay_store = VolatileHandshakeReplayStore::default();
    let mut unrelated = Pair::new();

    let (wrong_pin_pending, wrong_pin_init) = alice
        .initiate_handshake(mallory.public_key())
        .expect("create wrong-responder-pin init");
    let (_, wrong_pin_response) = bob
        .respond_to_handshake(alice.public_key(), wrong_pin_init, &replay_store)
        .expect("Bob creates response under his own identity");
    assert!(wrong_pin_pending
        .process_response(&alice, wrong_pin_response)
        .is_err());

    let (wrong_initiator_pending, wrong_initiator_init) = alice
        .initiate_handshake(bob.public_key())
        .expect("create init");
    let (wrong_pin_responder, wrong_pin_response) = bob
        .respond_to_handshake(mallory.public_key(), wrong_initiator_init, &replay_store)
        .expect("responder creates a context-bound response");
    assert!(wrong_initiator_pending
        .process_response(&alice, wrong_pin_response)
        .is_err());
    drop(wrong_pin_responder);

    let (_, replay_init) = alice
        .initiate_handshake(bob.public_key())
        .expect("create replay fixture");
    bob.respond_to_handshake(alice.public_key(), replay_init.clone(), &replay_store)
        .expect("first copy accepted");
    assert!(matches!(
        bob.respond_to_handshake(alice.public_key(), replay_init, &replay_store),
        Err(CryptoError::HandshakeReplayDetected)
    ));

    let (mutated_pending, mut mutated_init) = alice
        .initiate_handshake(bob.public_key())
        .expect("create mutable init");
    let mut mutated_wire = mutated_init.to_bytes().expect("encode init");
    if let Handshake::Init(ref mut value) = mutated_init {
        value.noise_message[0] ^= 1;
    }
    let (_, mutated_response) = bob
        .respond_to_handshake(alice.public_key(), mutated_init, &replay_store)
        .expect("modified but valid ephemeral can be processed");
    assert!(mutated_pending
        .process_response(&alice, mutated_response)
        .is_err());
    mutated_wire.truncate(1);
    assert!(Handshake::from_bytes(&mutated_wire).is_err());

    let (_, mut invalid_public_init) = alice
        .initiate_handshake(bob.public_key())
        .expect("create invalid-public-key fixture");
    if let Handshake::Init(ref mut value) = invalid_public_init {
        value.noise_message[..32].fill(0);
    }
    assert!(bob
        .respond_to_handshake(alice.public_key(), invalid_public_init, &replay_store)
        .is_err());

    for offset in [0, 32, 80, 120] {
        let (pending, init) = alice
            .initiate_handshake(bob.public_key())
            .expect("create response-mutation fixture");
        let (responder, mut response) = bob
            .respond_to_handshake(alice.public_key(), init, &replay_store)
            .expect("create valid response");
        if let Handshake::Response(ref mut value) = response {
            let index = offset.min(value.noise_message.len() - 1);
            value.noise_message[index] ^= 1;
        }
        assert!(
            pending.process_response(&alice, response).is_err(),
            "mutated encrypted response accepted; seed {seed:#018x}"
        );
        drop(responder);
    }

    let (pending, init) = alice
        .initiate_handshake(bob.public_key())
        .expect("start malformed-response fixture");
    let (responder, mut response) = bob
        .respond_to_handshake(alice.public_key(), init, &replay_store)
        .expect("create valid response");
    if let Handshake::Response(ref mut value) = response {
        value.noise_message.truncate(10);
    }
    assert!(pending.process_response(&alice, response).is_err());
    drop(responder);

    let (pending, init) = alice
        .initiate_handshake(bob.public_key())
        .expect("start finish-mutation fixture");
    let (responder, response) = bob
        .respond_to_handshake(alice.public_key(), init, &replay_store)
        .expect("create response");
    let (mut finish, _) = pending
        .process_response(&alice, response)
        .expect("create valid finish");
    if let Handshake::Finish(ref mut value) = finish {
        let last_byte = value.noise_message.len() - 1;
        value.noise_message[last_byte] ^= 1;
    }
    assert!(responder.complete(finish).is_err());

    let (original_pending, original_init) = alice
        .initiate_handshake(bob.public_key())
        .expect("start original handshake");
    let (original_responder, original_response) = bob
        .respond_to_handshake(alice.public_key(), original_init, &replay_store)
        .expect("create original response");
    let (replay_finish, _) = original_pending
        .process_response(&alice, original_response.clone())
        .expect("complete initiator side");
    let (new_pending, new_init) = alice
        .initiate_handshake(bob.public_key())
        .expect("start a distinct handshake");
    assert!(new_pending
        .process_response(&alice, original_response)
        .is_err());
    drop(original_responder);

    let (new_responder, _) = bob
        .respond_to_handshake(alice.public_key(), new_init, &replay_store)
        .expect("create distinct responder state");
    assert!(new_responder.complete(replay_finish).is_err());

    let wrong_order = Handshake::Finish(HandshakeFinish {
        version: 2,
        noise_message: vec![],
    });
    assert!(matches!(
        bob.respond_to_handshake(alice.public_key(), wrong_order, &replay_store),
        Err(CryptoError::InvalidHandshakeState)
    ));
    assert!(matches!(
        Handshake::from_bytes(&[0xff]),
        Err(CryptoError::MalformedMessage)
    ));

    let (_, mut wrong_version) = alice
        .initiate_handshake(bob.public_key())
        .expect("create version fixture");
    if let Handshake::Init(ref mut value) = wrong_version {
        value.version = 99;
    }
    assert!(matches!(
        bob.respond_to_handshake(alice.public_key(), wrong_version, &replay_store),
        Err(CryptoError::InvalidProtocolVersion { received: 99 })
    ));

    let (parallel_a_pending, parallel_a_init) = alice
        .initiate_handshake(bob.public_key())
        .expect("start first simultaneous session");
    let (parallel_b_pending, parallel_b_init) = alice
        .initiate_handshake(bob.public_key())
        .expect("start second simultaneous session");
    let (parallel_a_responder, parallel_a_response) = bob
        .respond_to_handshake(alice.public_key(), parallel_a_init, &replay_store)
        .expect("accept first independent handshake");
    let (parallel_b_responder, parallel_b_response) = bob
        .respond_to_handshake(alice.public_key(), parallel_b_init, &replay_store)
        .expect("accept second independent handshake");
    let (parallel_a_finish, _) = parallel_a_pending
        .process_response(&alice, parallel_a_response)
        .expect("finish first independent handshake");
    let (parallel_b_finish, _) = parallel_b_pending
        .process_response(&alice, parallel_b_response)
        .expect("finish second independent handshake");
    assert!(parallel_a_responder.complete(parallel_a_finish).is_ok());
    assert!(parallel_b_responder.complete(parallel_b_finish).is_ok());

    let (passive_pending, passive_init) = alice
        .initiate_handshake(bob.public_key())
        .expect("create passive inspection handshake");
    let (passive_responder, passive_response) = bob
        .respond_to_handshake(alice.public_key(), passive_init.clone(), &replay_store)
        .expect("create passive inspection response");
    let (passive_finish, _) = passive_pending
        .process_response(&alice, passive_response.clone())
        .expect("create passive inspection finish");
    let flights = [
        passive_init.to_bytes().expect("encode first flight"),
        passive_response.to_bytes().expect("encode second flight"),
        passive_finish.to_bytes().expect("encode third flight"),
    ];
    for flight in &flights {
        assert!(
            !flight
                .windows(alice.public_key().as_bytes().len())
                .any(|window| window == alice.public_key().as_bytes()),
            "initiator identity leaked in serialized handshake; seed {seed:#018x}"
        );
        assert!(
            !flight
                .windows(bob.public_key().as_bytes().len())
                .any(|window| window == bob.public_key().as_bytes()),
            "responder identity leaked in serialized handshake; seed {seed:#018x}"
        );
        assert!(!flight.windows(32).any(|window| window == &[0x71; 32]));
        assert!(!flight.windows(32).any(|window| window == &[0x72; 32]));
    }
    assert!(passive_responder.complete(passive_finish).is_ok());

    let unrelated_message = unrelated
        .alice
        .encrypt(b"unrelated session remains usable", b"test")
        .expect("existing session encrypts after unrelated handshake attempts");
    assert_eq!(
        unrelated
            .bob
            .decrypt(&unrelated_message, b"test")
            .expect("existing session decrypts after unrelated handshake attempts")
            .as_slice(),
        b"unrelated session remains usable"
    );
}
