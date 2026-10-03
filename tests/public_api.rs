use aether_crypto::{
    CryptoError, Handshake, HandshakeFinish, Identity, IdentityPublicKey, Message, Session,
    VolatileHandshakeReplayStore,
};

#[test]
fn application_api_completes_handshake_and_session_lifecycle() {
    let alice = Identity::from_secret_bytes(&[81; 32]).expect("valid identity seed");
    let bob = Identity::from_secret_bytes(&[82; 32]).expect("valid identity seed");
    let replay_store = VolatileHandshakeReplayStore::default();

    let (alice_pending, init) = alice
        .initiate_handshake(bob.public_key())
        .expect("start handshake");
    let init = Handshake::from_bytes(&init.to_bytes().expect("encode init")).expect("decode init");
    let (bob_pending, response) = bob
        .respond_to_handshake(alice.public_key(), init, &replay_store)
        .expect("respond");
    let response = Handshake::from_bytes(&response.to_bytes().expect("encode response"))
        .expect("decode response");
    let (finish, mut alice_session) = alice_pending
        .process_response(&alice, response)
        .expect("process response");
    let finish =
        Handshake::from_bytes(&finish.to_bytes().expect("encode finish")).expect("decode finish");
    let mut bob_session = bob_pending.complete(finish).expect("complete handshake");

    let message = alice_session
        .encrypt(b"hello", b"context")
        .expect("encrypt");
    let decoded =
        Message::from_bytes(&message.to_bytes().expect("encode message")).expect("decode message");
    assert_eq!(
        bob_session
            .decrypt(&decoded, b"context")
            .expect("decrypt")
            .as_slice(),
        b"hello"
    );

    let storage_key = [0x84; 32];
    let state = bob_session
        .export_state(&storage_key)
        .expect("export session state");
    let mut restored = Session::import_state(&state, &storage_key).expect("import session state");
    let reply = restored
        .encrypt(b"reply", b"context")
        .expect("encrypt reply");
    assert_eq!(
        alice_session
            .decrypt(&reply, b"context")
            .expect("decrypt reply")
            .as_slice(),
        b"reply"
    );
}

#[test]
fn application_api_returns_typed_errors_for_invalid_flight_and_key_length() {
    let identity = Identity::from_secret_bytes(&[91; 32]).expect("valid identity seed");
    let replay_store = VolatileHandshakeReplayStore::default();
    let wrong_flight = Handshake::Finish(HandshakeFinish {
        version: 2,
        noise_message: vec![],
    });

    assert!(matches!(
        identity.respond_to_handshake(
            IdentityPublicKey::from_bytes([92; 32]),
            wrong_flight,
            &replay_store
        ),
        Err(CryptoError::InvalidHandshakeState)
    ));
    assert!(matches!(
        Identity::from_secret_bytes(&[0; 31]),
        Err(CryptoError::InvalidKeyLength { expected: 32 })
    ));
}
