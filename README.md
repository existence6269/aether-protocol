# aether-crypto

`aether-crypto` is Aether's independent experimental cryptography crate. It
implements an Aether application protocol using the Noise Protocol Framework's
XX handshake and a 1:1 Double Ratchet. The implementation is **experimental,
unaudited, and not production-ready**. Passing its test suite does not prove
security.

It is not a Matrix client, does not expose networking endpoints, and does not
implement account management, a server, transport, secure storage, or Tauri
integration. Aether is its own application protocol; it does not claim
compatibility with Signal, libsignal, Matrix, or another messaging protocol.

## Protocol at a glance

| Concern | Current implementation |
| --- | --- |
| Identity and pinning | Ed25519 signing keypair |
| Handshake | `Noise_XX_25519_ChaChaPoly_BLAKE2s`, implemented with Snow |
| Noise static key | Domain-separated X25519 derivation from the Ed25519 seed |
| Noise ephemeral and ratchet DH | X25519 |
| Noise handshake key schedule | Noise chaining key, handshake hash, and Split |
| Ratchet root derivation | HKDF-SHA256 over both Noise Split outputs and final handshake hash |
| Ratchet message encryption/authentication | AES-256-GCM |
| Public protocol serialization | Versioned Postcard messages |
| Secret cleanup | Zeroizing wrappers where practical; best-effort only |

Ed25519 remains the long-term Aether identity and signing system. Noise uses
X25519 for its static and ephemeral DH tokens. The Noise static private key is
derived separately from the Ed25519 seed using HKDF-SHA256, with the Ed25519
public key as salt and the label
`aether/noise/xx/static-x25519/v1`; this is domain separation, not conversion
of an Ed25519 point into an X25519 point. The Ed25519 key signs a binding
between the pinned identity and its Noise static public key. Importing the same
identity seed reproduces the same separate Noise static key. Protecting the
seed is therefore necessary to protect both keys.

The caller must obtain and pin/authenticate the peer's Ed25519 public identity
key using a trusted mechanism. This crate does not decide whether an identity
key belongs to a particular person.

## Noise XX handshake

The selected Noise protocol name is
`Noise_XX_25519_ChaChaPoly_BLAKE2s`. Its standard token sequence is:

```text
-> e
<- e, ee, s, es
-> s, se
```

The crate's versioned `Handshake::{Init, Response, Finish}` wrappers each carry
one Noise handshake message. Flight 1 carries the initiator's Noise ephemeral
public key in clear; it carries no Aether identity. Flight 2 carries the
responder ephemeral key in clear; Noise encrypts the responder static public
key and payload. Flight 3 carries the encrypted initiator static public key
and payload. The payloads contain Ed25519 public identities, role-specific
Ed25519 signatures binding the identities to Noise static keys, and the
corresponding fresh Double Ratchet bootstrap public key. No private identity,
Noise static, Noise ephemeral, or ratchet-bootstrap key is serialized.

The local Noise prologue is the fixed-order Postcard encoding of the profile
label `aether/noise-xx/double-ratchet/v2`, Aether profile version 2, and both
pinned Ed25519 identities in initiator/responder order. Noise incorporates the
prologue and all handshake message data into its handshake hash `h` and
chaining key `ck`. The responder signature binds its role, both pinned
identities, the hash after Flight 1, responder Noise static public key, and
responder ratchet-bootstrap public key. The initiator signature binds its
role, both identities, the hash after Flight 2, both Noise static public keys,
and initiator ratchet-bootstrap public key. Each signature is verified against
the caller-pinned Ed25519 identity. The final Noise hash binds the complete
Noise exchange, including encrypted payloads.

Snow's successful Noise AEAD processing and the `es`/`se` DH tokens provide
Noise key-possession confirmation; the implementation does not add a separate
custom HMAC confirmation scheme. The initiator authenticates the responder
after processing Flight 2. The responder authenticates the initiator after
processing Flight 3. Identity/static-key substitution, changed prologues,
altered encrypted payloads, and non-contributory X25519 inputs fail validation.

### Noise Split to Double Ratchet root

```text
Noise Split(ck_final, empty) -> (K_i_to_r, K_r_to_i)

DR_root = HKDF-SHA256(
    salt = h_final,
    IKM  = K_i_to_r || K_r_to_i,
    info = "aether/double-ratchet/root/noise-xx/v1",
    L    = 32 bytes,
)
```

`h_final` is public context and is never used alone as key material. `K_i_to_r`
and `K_r_to_i` are the two 32-byte, direction-ordered outputs of Noise's
specified Split; the endpoint role does not change their concatenation order.
The resulting `DR_root` is used only as the root input to the existing
Double Ratchet initializer. Fresh, distinct ratchet-bootstrap keypairs are
exchanged inside the encrypted Noise payloads, so Noise `e`/`s` keys are not
reused as ratchet keys. The existing initializer performs its existing initial
X25519 DH and chain-key derivation; ratchet message keys and AES-GCM keys
remain derived by the Double Ratchet code.

The raw Split boundary is isolated in private
[`noise_split.rs`](./src/noise_split.rs). It rejects unfinished Noise states,
obtains the Snow Split outputs, immediately wraps/zeroizes them after use, and
returns only the domain-separated Aether ratchet root. Split outputs are never
part of public types, serialization, or logging. Snow's
`dangerously_get_raw_split` API is explicitly risky; `Cargo.toml` pins Snow
0.10.0 so upgrades require review of this boundary and the output schedule.
Snow's state internals and its handling of temporary secret copies must also be
re-reviewed on upgrades.

Snow is an implementation of the Noise framework, not an audit or security
guarantee. Its use does not make the full Aether protocol secure or formally
verified. Aether's Ed25519-to-Noise-static binding, prologue, application root
derivation, replay store, and Double Ratchet integration remain Aether-specific
and require independent cryptographic review.

## Double Ratchet and message lifecycle

After the handshake, peers initialize opposite sides of an
initiator-to-responder initial chain. Each local `Session` contains:

- current root key;
- optional sending and receiving chain keys;
- current local X25519 ratchet private key and the remote public key;
- sending, receiving, and previous-chain counters;
- skipped message keys indexed by remote ratchet public key and message number;
- retired remote DH public keys used to identify stale-generation replays.

### Sending

`Session::encrypt` derives the next message key and next chain key from the
current sending chain using the domain-separated HKDF-SHA256 chain KDF. It does
not randomly generate an independent message key. The message key is used for
one AES-256-GCM encryption and is zeroized on drop where supported. Each message
uses a fresh random 96-bit GCM nonce.

The versioned public header contains the sender's ratchet public key, previous
chain length, and message number. The encoded header and caller-supplied
associated data are length-delimited and authenticated as AES-GCM associated
data. Applications must supply the same associated data when decrypting.

### Receiving, reordering, and replay handling

`Session::decrypt` validates the header and bounds, derives required skipped
keys, and authenticates with AES-GCM. Work is performed on a temporary state
copy; a failed authentication does not commit ratchet advancement. A skipped
key is consumed only when its message authenticates. Replays of consumed keys
are rejected.

When a peer DH public key changes, the receiver closes the previous receive
chain up to the message's advertised previous-chain length, performs the DH
ratchet, derives a new receiving chain, generates a fresh local DH ratchet key,
and derives a new sending chain. Delayed messages can still be decrypted with
stored skipped keys from old generations. Once a remote DH generation has been
retired and its skipped keys have been consumed, packets from that generation
are rejected as stale/replayed rather than being interpreted as a new ratchet.

The default skipped-message limit is 2,000 keys per session and applications
can lower or raise it up to 20,000. Retired remote DH generations are retained
up to 20,000. If either bound is reached, the operation fails explicitly; the
implementation does not silently evict replay history or skipped keys. A
session at the retired-generation cap cannot process a further DH transition.

## Wire and local state formats

`Handshake` and `Message` are public protocol values. Use their
`to_bytes`/`from_bytes` methods instead of serializing internal ratchet state.
Handshake wrappers use Aether version 2 and carry bounded Noise XX wire
messages, up to 4 KiB each. Flight 1 contains the initiator Noise ephemeral
public key; Flights 2 and 3 contain the Noise-encrypted static keys and
identity/bootstrap payloads. A serialized ratchet message and ciphertext are
each limited to 1 MiB. Associated data is limited to 64 KiB. Malformed and
oversized inputs return errors rather than being accepted as successful
messages.

### First-flight replay storage

`Identity::respond_to_handshake` requires a caller-provided
`HandshakeReplayStore`. Before returning a responder state, Aether computes a
domain-separated SHA-256 `HandshakeReplayId` from the protocol profile,
responder identity, and canonical Flight 1 bytes, then invokes the store's
atomic `check_and_record` operation. A durable implementation should commit an
insert-if-absent (for example, a database unique constraint) before reporting
`Inserted`. Duplicate flights are rejected; storage errors and capacity
failures stop the handshake. Do not use timestamps alone, and do not silently
evict replay identifiers while claiming protection for them.

`VolatileHandshakeReplayStore` provides atomic duplicate detection within its
process lifetime, with a bounded 20,000-entry default. Its history is lost on
drop or process restart, so it does **not** prevent replay across restarts.
Applications that accept that weaker guarantee may use it; callers needing
restart-persistent protection must implement the public store trait over
durable storage. The caller's retention policy determines the replay window.
An accepted first-flight identifier remains recorded even if a later
handshake flight fails.

Pending Noise states are one-use. Replayed Flights 2/3 or flights from a
different handshake fail Noise authentication/state checks. A Noise parse or
authentication failure consumes and drops that pending handshake and yields
no `Session`. Snow documents that a failed `read_message` state should not be
reused; Aether follows that rule.

`Session::export_state(&storage_key)` requires a caller-provided 32-byte
storage key and returns an encrypted snapshot. The snapshot uses AES-256-GCM
with a fresh random nonce and the domain-separated associated-data label
`aether/double-ratchet/state-snapshot/v1`. Its authenticated plaintext contains
root and chain keys, the local DH private key, skipped message keys, counters,
and replay-generation history; the storage key is never included. Treat the
returned value as ciphertext, but still keep it in protected storage and do
not log or transmit it without considering application-level metadata leakage.

The caller remains responsible for generating, persisting, and protecting the
storage key. `Session::import_state(&snapshot, &storage_key)` authenticates and
decrypts before parsing any ratchet state. A wrong key or modified nonce or
ciphertext fails authentication; malformed envelopes and unsupported versions
are rejected. The encrypted envelope version is separate from the inner local
snapshot schema version and from the wire-message version. Decrypted plaintext
and temporary state structures use the crate's zeroization mechanisms where
practical.

`Identity::export_secret_bytes` returns the Ed25519 seed in a zeroizing
container; the domain-separated Noise static private key is deterministically
derived from that seed. Protect the seed before storing it.
`SecretBytes` provides best-effort zeroization, but callers should keep
plaintext and secret copies short-lived.

## Application-facing API

Applications should use crate-root types:

- `Identity` / `IdentityPublicKey` — create/import an identity and access its
  public key.
- `Handshake` — versioned public handshake flight; Postcard byte conversion.
- `InitiatorHandshake` / `ResponderHandshake` — one-use pending handshake
  states with typed flight sequencing.
- `Session` — encrypt/decrypt, skipped-key policy, and state import/export.
- `Message` — public encrypted payload and Postcard byte conversion.
- `CryptoError` — typed failure results.

The AEAD, KDF, X25519 key internals, handshake implementation, serialization
helpers, and `DoubleRatchetState` are private implementation details. A typical
application flow is:

```rust,no_run
use aether_crypto::{Handshake, Identity, Message, VolatileHandshakeReplayStore};

let alice = Identity::generate()?;
let bob = Identity::generate()?;
let replay_store = VolatileHandshakeReplayStore::default();

let (alice_pending, init) = alice.initiate_handshake(bob.public_key())?;
let init = Handshake::from_bytes(&init.to_bytes()?)?;
let (bob_pending, response) =
    bob.respond_to_handshake(alice.public_key(), init, &replay_store)?;
let response = Handshake::from_bytes(&response.to_bytes()?)?;
let (finish, mut alice_session) = alice_pending.process_response(&alice, response)?;
let finish = Handshake::from_bytes(&finish.to_bytes()?)?;
let mut bob_session = bob_pending.complete(finish)?;

let outgoing = alice_session.encrypt(b"hello", b"conversation-context")?;
let outgoing = Message::from_bytes(&outgoing.to_bytes()?)?;
let plaintext = bob_session.decrypt(&outgoing, b"conversation-context")?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

The example omits network transport, peer-key verification UX, account
management, storage protection, and durable replay storage. Use a persistent
`HandshakeReplayStore` implementation where first-flight replay protection
must survive restarts.

## Performance characteristics

There are no dedicated microbenchmarks or throughput claims yet. Performance
depends on CPU, compiler/build profile, operating-system CSPRNG, message size,
and how often DH ratchets and out-of-order deliveries occur. The following
describes the current implementation's work and scaling, not benchmark results:

- **In-order message:** one HKDF-SHA256 chain step, one AES-256-GCM operation,
  one OS-random nonce, and bounded message/header serialization.
- **Handshake:** three Noise XX flights, X25519 `ee`/`es`/`se` operations,
  Ed25519 identity-binding signatures, Noise's internal chaining/KDF work,
  and one Aether HKDF from the two Noise Split outputs to the ratchet root.
- **DH ratchet transition:** in addition to normal chain work, X25519 DH
  operations and root-key HKDF steps are performed. A remote-key change derives
  receive and send chains.
- **Out-of-order gap of `g` messages:** up to `g` message keys are derived and
  stored before the target message is authenticated. Time and temporary work
  scale linearly with `g`; the configured skipped-key cap bounds the amount.
- **Replay lookup:** skipped and retired keys are held in hash maps/sets, giving
  expected constant-time lookup. Retired history consumes roughly 32 bytes per
  public key plus collection overhead, up to the 20,000-generation cap.
- **Atomicity cost:** ratchet operations duplicate the current state before
  committing. The current implementation therefore copies skipped-key
  entries during a message operation; this cost grows linearly with the number
  of retained skipped keys. This is a known performance trade-off for
  rollback-on-authentication-failure and a candidate for future optimization
  that must preserve atomicity.
- **State export:** sorting retired-generation keys makes export
  `O(r log r)` for `r` retired generations; encoding size is capped at 2 MiB.
- **Parsing/replay:** handshake/message/state inputs are length-limited before
  processing; parsing work scales with accepted input size within those caps.
  Flight 1 replay lookup is expected constant time for the provided volatile
  hash-set store; durable-store performance depends on the caller's backend.

## Security Status / Testing

The Aether Protocol implementation is **experimental and has not undergone an
independent security audit**. It has been extensively battle-tested with
randomized integration and adversarial tests, but those tests are regression
and robustness evidence only.

The Noise implementation dependency, Snow 0.10.0, is also unaudited for this
application. Aether enables Snow's explicitly named `risky-raw-split` feature
to derive a separate Double Ratchet root from Noise Split outputs. The tiny
private wrapper restricts access to completed handshakes and zeroizes its
returned Split copies, but Snow internals and transient copies are outside that
wrapper. This dependency feature and any Snow upgrade require explicit
cryptographic/security review.

The battle tests exercise message reordering, duplication, drops, replay
attempts, delayed delivery across ratchet generations, DH ratchet generation
changes, state persistence and restoration, malformed or mutated inputs,
authentication failures, and handshake attacks. The scenarios and their
deterministic seeds are recorded in [`tests/battle.rs`](./tests/battle.rs).
Each scenario uses a reproducible custom test RNG seed; a scenario can be
replayed with its listed seed to investigate a failure. The cryptographic
primitives in normal protocol operation continue to use the OS CSPRNG.

Extensive battle testing does **not** constitute a formal security audit or
formal verification, and it does not guarantee the absence of cryptographic
or implementation vulnerabilities. It also does not establish that every
possible input, interleaving, platform, or failure condition has been tested.
Do not interpret passing tests as evidence that the protocol is production
secure.

The current seeded stress workloads include 10,000 randomized conversation
messages, 64 DH generations with delayed messages, 1,200
persistence-simulation messages, and thousands of deterministic
malformed/mutated inputs. In the most recent recorded workspace run, the full
suite passed and the six battle integration tests took about 19.9 seconds in
that development environment. This is a test-runtime observation, not a
cryptographic throughput benchmark. No dedicated release-mode benchmark
results are available; add benchmarks on target hardware before making
latency, throughput, or resource-budget decisions.

## Battle-test coverage

`tests/battle.rs` contains six reusable deterministic integration simulations:

| Scenario | Workload | Seed |
| --- | ---: | --- |
| Randomized two-party conversation | 10,000 messages plus 32 continuation messages | `0x0000A37E20261001` |
| Multi-generation delayed messages | 64 DH generations, 1,024 generation messages plus continuation | `0x0000A37E20261002` |
| State export/import torture | 1,200 mirrored randomized messages plus repeated restores and delayed deliveries | `0x0000A37E20261003` |
| Malicious wire mutation | 5,000 mixed packet mutations, 2,000 AAD failures, 2,000 authenticated-message mutations, 2,000 state mutations | `0x0000A37E20261004` |
| Unreliable in-memory transport | 3,000 transport ticks, randomized sends/drops/duplicates/restarts plus reconnect traffic | `0x0000A37E20261005` |
| Identity/handshake attack suite | Wrong pins, substituted identities/ephemerals, altered Noise flights, wrong version, replay/order/malformed cases | `0x0000A37E20261006` |

The RNG used for test scheduling, mutations, and test payloads is deterministic.
Cryptographic keys, Noise ephemerals, and message nonces in production paths
continue to use the OS CSPRNG.
Stress-test success is useful regression evidence; it is not formal
verification, fuzzing coverage proof, or a security audit.

## Assumptions and limitations

- Peer identity keys are correctly pinned/authenticated by the caller.
- `OsRng`, Snow, RustCrypto primitives, dependencies, compiler, and operating
  system behave as expected. Memory zeroization is best-effort and cannot erase
  all allocator/compiler/OS copies or caller-created copies. In particular,
  the private Split wrapper cannot guarantee that Snow erased every internal
  copy when its handshake state is dropped.
- Durable Flight 1 replay protection requires an application-provided store
  with atomic, committed insert-if-absent semantics. The included volatile
  store loses replay history on restart.
- Persisted ratchet snapshots are AES-256-GCM encrypted with a caller-managed
  32-byte storage key; protection and recovery of that key are the caller's
  responsibility.
- No transport security, delivery acknowledgement, identity directory,
  identity rotation/revocation UX, multi-device or group protocol, secure
  storage, traffic-analysis mitigation, or denial-of-service controls are
  provided.
- The ratchet's storage limits can eventually prevent additional skipped
  messages or DH generations from being accepted; applications must handle
  these explicit errors.
- The handshake and ratchet have not received independent cryptographic
  review, formal verification, or production hardening.

Run the checks from the workspace root:

```powershell
cargo fmt --all
cargo check --workspace
cargo test --workspace
```

Treat this as experimental research code only.
