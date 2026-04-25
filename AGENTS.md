## go-doubleratchet

Go implementation of the Signal Double Ratchet protocol with header encryption,
post-quantum (SPQR), and hybrid Triple Ratchet variants.

### Architecture

```
session.go          — Base Double Ratchet (Session)
session_he.go       — Header Encryption variant (HESession)
session_spqr.go     — Sparse Post-Quantum Ratchet (SPQRSession)
session_tr.go       — Triple Ratchet / Hybrid (TripleRatchetSession)
config.go           — Config with identity keys, HKDF info, MaxSkip
keys.go             — Public aliases (InitAlice/InitBob/GenerateKeyPair)
message.go          — Message, Header, SCKAHeader types
errors.go           — Sentinel errors
```

### Internal packages

```
internal/crypto/    — X25519 DH, header encrypt/decrypt (HENCRYPT/HDECRYPT)
internal/kdf/       — Chain KDF (HMAC-SHA256), root KDF (HKDF), hybrid KDF
internal/state/     — ReceiverChains (circular buffer of 5), skipped key Storage, Invariants
internal/suite/     — AES-256-CBC + HMAC-SHA256 AEAD (Encrypt-then-MAC)
```

### Key design decisions

- **Chain KDF constants**: message key = `HMAC(ck, 0x01)`, next chain key = `HMAC(ck, 0x02)` (matches Signal spec and libsignal Rust)
- **Receiver chains**: circular buffer of up to 5 chains (matches libsignal `MAX_RECEIVER_CHAINS`), enabling decryption of messages from previous DH epochs
- **Identity binding**: `Config.LocalIdentityKey` / `Config.RemoteIdentityKey` auto-prepend `sender_identity || receiver_identity` to AD in MAC (direction-aware, matches libsignal)
- **AEAD**: AES-256-CBC + HMAC-SHA256 with 32-byte MAC tag (Encrypt-then-MAC, MAC verified before decrypt)
- **Deferred DH ratchet**: send-side ratchet deferred to next `Encrypt()` via `dhRatchetPerformed` flag
- **Secure deletion**: all superseded key material zeroed before replacement (§8.1)
- **No persistence**: sessions are in-memory only; no serialization format

### Reference implementation

Validated against libsignal Rust at `rust/protocol/src/`:
- `ratchet/keys.rs` — chain/root key derivation
- `double_ratchet.rs` — ratchet state machine
- `protocol.rs` — message format, MAC computation

### Agent instructions

- Use TDD by default. Start with a failing test, make the smallest change to pass it.
- Run `go test ./...` after each meaningful step.
- For bug fixes, reproduce with a test before changing implementation.
- Constant-time comparison (`subtle.ConstantTimeCompare`) for all security-critical comparisons.
- Zero superseded key material before replacing (call `zeroBytes`).
- MAC must be verified before AES-CBC decryption (padding oracle prevention).
- `buildAD(header, ad, sending)` handles identity prefix direction — `sending=true` for Encrypt, `sending=false` for Decrypt.
- ReceiverChains are looked up by ratchet public key. `Decrypt` distinguishes current chain, old chain (in buffer), and new epoch (triggers DH ratchet).
- `Invariants.Record(...)` must be called before any state mutation in Decrypt paths, enabling rollback on auth failure.
