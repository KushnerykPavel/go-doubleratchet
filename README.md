# go-doubleratchet

[![Go Reference](https://pkg.go.dev/badge/github.com/KushnerykPavel/go-doubleratchet.svg)](https://pkg.go.dev/github.com/KushnerykPavel/go-doubleratchet)
[![CI](https://github.com/KushnerykPavel/go-doubleratchet/actions/workflows/ci.yml/badge.svg)](https://github.com/KushnerykPavel/go-doubleratchet/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/KushnerykPavel/go-doubleratchet)](https://goreportcard.com/report/github.com/KushnerykPavel/go-doubleratchet)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Go implementation of the Signal Double Ratchet protocol family:

- Base Double Ratchet (Signal spec section 3)
- Double Ratchet with header encryption (section 4)
- Sparse Post-Quantum Ratchet / SPQR (section 5)
- Triple Ratchet / hybrid EC+PQ (section 6)

> **Status:** Pre-1.0. The API may change between minor versions until a v1.0.0 tag is cut. Pin your dependency to a specific version.

## Table of Contents

- [Install](#install)
- [Which Mode Should I Use?](#which-mode-should-i-use)
- [Base Double Ratchet](#base-double-ratchet)
- [Header Encryption](#header-encryption)
- [Sparse Post-Quantum Ratchet](#sparse-post-quantum-ratchet)
- [Triple Ratchet](#triple-ratchet)
- [Configuration](#configuration)
- [Associated Data](#associated-data)
- [Errors](#errors)
- [Session Lifecycle](#session-lifecycle)
- [Out-of-Order Messages](#out-of-order-messages)
- [SCKA Provider Contract](#scka-provider-contract)
- [Public Types](#public-types)
- [Exported Constants](#exported-constants)
- [Sub-Packages](#sub-packages)
- [Security Notes](#security-notes)
- [Runnable Examples](#runnable-examples)
- [Protocol Specs](#protocol-specs)
- [Contributing](#contributing)

## Install

```sh
go get github.com/KushnerykPavel/go-doubleratchet
```

Requires Go 1.26.1 or later (see `go.mod`).

## Which Mode Should I Use?

| Mode | Go type | Use when | Main tradeoff |
|---|---|---|---|
| Base Double Ratchet | `*doubleratchet.Session` | You need forward secrecy and break-in recovery with compact headers. | Headers expose ratchet public key and counters. |
| Header Encryption | `*doubleratchet.HESession` | You want to hide message ordering/session metadata in headers. | Requires shared header keys from the handshake. |
| SPQR | `*doubleratchet.SPQRSession` | You need post-quantum ratcheting without per-message PQ key exchange. | Requires a production `scka.Provider`. |
| Triple Ratchet | `*doubleratchet.TripleRatchetSession` | You want hybrid classical and post-quantum security. | Carries both EC and SCKA header data. |

All modes take an initial 32-byte-or-longer shared secret from an external handshake such as X3DH or PQXDH. The library does not implement the handshake itself.

## Base Double Ratchet

Base mode uses an X25519 DH ratchet plus symmetric sending and receiving chains. Alice initializes with Bob's initial ratchet public key; Bob initializes with the matching key pair.

```go
package main

import (
	"fmt"
	"log"

	doubleratchet "github.com/KushnerykPavel/go-doubleratchet"
)

func main() {
	sharedSecret := []byte("0123456789abcdef0123456789abcdef")

	bobPriv, bobPub, err := doubleratchet.GenerateKeyPair()
	if err != nil {
		log.Fatal(err)
	}
	bobKeyPair := doubleratchet.KeyPair{PrivateKey: bobPriv, PublicKey: bobPub}

	// Use BindIdentities to create AD that prevents cross-session replay.
	// senderPK and receiverPK come from your handshake (e.g. X3DH identity keys).
	ad := doubleratchet.BindIdentities(senderIdentityPK, receiverIdentityPK)

	alice, err := doubleratchet.InitAlice(sharedSecret, bobPub, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer alice.Close()

	bob, err := doubleratchet.InitBob(sharedSecret, bobKeyPair, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer bob.Close()

	msg, err := alice.Encrypt([]byte("hello bob"), ad)
	if err != nil {
		log.Fatal(err)
	}

	plaintext, err := bob.Decrypt(msg, ad)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(string(plaintext))
}
```

`Encrypt` returns a `doubleratchet.Message`, which contains a typed `Header` and `Ciphertext`.

> **Naming:** `InitAlice`/`InitBob` are convenience aliases for `InitInitiator`/`InitResponder`. Both sets are equivalent — use whichever reads better in your code. The same applies to HE, SPQR, and Triple Ratchet variants.

## Header Encryption

Header encryption hides the Double Ratchet header. Use `EncryptHE` and `DecryptHE`; the embedded base `Encrypt` and `Decrypt` methods on `HESession` intentionally return `ErrInvalidTransition`.

```go
package main

import (
	crand "crypto/rand"
	"log"

	doubleratchet "github.com/KushnerykPavel/go-doubleratchet"
)

func main() {
	sharedSecret := []byte("0123456789abcdef0123456789abcdef")
	ad := []byte("conversation-123")

	bobPriv, bobPub, err := doubleratchet.GenerateKeyPair()
	if err != nil {
		log.Fatal(err)
	}
	bobKeyPair := doubleratchet.KeyPair{PrivateKey: bobPriv, PublicKey: bobPub}

	var sharedHKA [32]byte  // Alice's initial sending header key.
	var sharedNHKB [32]byte // Bob's initial next receiving header key.
	if _, err := crand.Read(sharedHKA[:]); err != nil {
		log.Fatal(err)
	}
	if _, err := crand.Read(sharedNHKB[:]); err != nil {
		log.Fatal(err)
	}

	alice, err := doubleratchet.InitAliceHE(sharedSecret, bobPub, sharedHKA, sharedNHKB, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer alice.Close()

	bob, err := doubleratchet.InitBobHE(sharedSecret, bobKeyPair, sharedHKA, sharedNHKB, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer bob.Close()

	encHeader, msg, err := alice.EncryptHE([]byte("hello with private headers"), ad)
	if err != nil {
		log.Fatal(err)
	}

	_, err = bob.DecryptHE(encHeader, msg, ad)
	if err != nil {
		log.Fatal(err)
	}
}
```

`EncryptHE` returns an `EncryptedHeader` plus a `Message`. In HE mode, the `Message.Header` field is not used for transport; send the encrypted header bytes alongside the ciphertext.

## Sparse Post-Quantum Ratchet

SPQR delegates post-quantum continuous key agreement to the `scka.Provider` interface. The `scka/testing` package includes `sckatest.MockSCKA` for tests and examples only; production callers must supply a real post-quantum SCKA implementation.

```go
package main

import (
	"log"

	doubleratchet "github.com/KushnerykPavel/go-doubleratchet"
	sckatest "github.com/KushnerykPavel/go-doubleratchet/scka/testing"
)

func main() {
	sharedSecret := []byte("0123456789abcdef0123456789abcdef")
	ad := []byte("conversation-123")

	aliceSCKA := &sckatest.MockSCKA{}
	bobSCKA := &sckatest.MockSCKA{}

	alice, err := doubleratchet.InitAliceSCKA(sharedSecret, aliceSCKA, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer alice.Close()

	bob, err := doubleratchet.InitBobSCKA(sharedSecret, bobSCKA, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer bob.Close()

	header, ciphertext, err := alice.Encrypt([]byte("post-quantum hello"), ad)
	if err != nil {
		log.Fatal(err)
	}

	_, err = bob.Decrypt(header, ciphertext, ad)
	if err != nil {
		log.Fatal(err)
	}
}
```

`Encrypt` returns a `*SCKAHeader` and ciphertext bytes. The header contains opaque SCKA message data plus the SPQR message number.

## Triple Ratchet

Triple Ratchet runs the base EC Double Ratchet and SPQR in parallel, then combines both message keys through the hybrid KDF. The shared secret is expanded internally into separate EC and SCKA secrets.

```go
package main

import (
	"log"

	doubleratchet "github.com/KushnerykPavel/go-doubleratchet"
	sckatest "github.com/KushnerykPavel/go-doubleratchet/scka/testing"
)

func main() {
	sharedSecret := []byte("0123456789abcdef0123456789abcdef")
	ad := []byte("conversation-123")

	bobPriv, bobPub, err := doubleratchet.GenerateKeyPair()
	if err != nil {
		log.Fatal(err)
	}
	bobKeyPair := doubleratchet.KeyPair{PrivateKey: bobPriv, PublicKey: bobPub}

	aliceSCKA := &sckatest.MockSCKA{}
	bobSCKA := &sckatest.MockSCKA{}

	alice, err := doubleratchet.InitAliceTripleRatchet(sharedSecret, bobPub, aliceSCKA, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer alice.Close()

	bob, err := doubleratchet.InitBobTripleRatchet(sharedSecret, bobKeyPair, bobSCKA, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer bob.Close()

	msg, err := alice.Encrypt([]byte("hybrid hello"), ad)
	if err != nil {
		log.Fatal(err)
	}

	_, err = bob.Decrypt(msg, ad)
	if err != nil {
		log.Fatal(err)
	}
}
```

`Encrypt` returns a `TripleRatchetMessage`, whose header contains both the EC `Header` and the `*SCKAHeader`.

## Configuration

Pass `nil` for defaults, or provide the same `Config` values on both sides of a session.

```go
cfg := &doubleratchet.Config{
	MaxSkip:     1000,
	KDFInfo:     []byte("MyAppDoubleRatchet"),
	HEKDFInfo:   []byte("MyAppHeaderEncryption"),
	EncryptInfo: []byte("MyAppPayloadEncryption"),
	HybridInfo:  []byte("MyAppHybridRatchet"),
}
```

`MaxSkip` bounds how many skipped message keys can be retained for out-of-order delivery. A zero `MaxSkip` means `DefaultMaxSkip` (`1000`). The info strings are HKDF domain-separation labels; both parties must use identical values or messages will not decrypt.

## Associated Data

Every encryption method accepts `ad []byte` as additional authenticated data. It is authenticated but not encrypted. Use it for stable transport context such as conversation ID, protocol version, sender/receiver identifiers, or transcript binding.

Use `BindIdentities(senderPK, receiverPK)` to construct a 64-byte AD prefix from both parties' identity public keys. This prevents cross-session replay of message key material and matches Signal spec section 3.3.

The same associated data must be provided to decrypt. A mismatch returns `ErrAuthFailure`.

## Errors

The root package exposes sentinel errors suitable for `errors.Is` or direct comparison:

| Error | Meaning |
|---|---|
| `ErrInvalidInput` | Malformed inputs, short shared secrets, invalid ratchet keys, or nil SCKA provider. |
| `ErrMaxSkipExceeded` | A received message would require retaining more skipped keys than `MaxSkip`. |
| `ErrSkippedKeyNotFound` | A skipped key is missing, usually because a message was replayed or state is desynchronized. |
| `ErrAuthFailure` | Ciphertext, header, or associated data authentication failed. |
| `ErrInvalidTransition` | The operation is invalid for the session state or mode. |
| `ErrSessionNotInitialized` | Bob tried to send before receiving Alice's first message. |
| `ErrEpochMismatch` | SPQR epoch advancement was inconsistent. |

Example:

```go
plaintext, err := bob.Decrypt(msg, ad)
switch err {
case nil:
	_ = plaintext
case doubleratchet.ErrAuthFailure:
	// Tampered ciphertext/header or associated-data mismatch.
default:
	return err
}
```

## Session Lifecycle

- Treat session structs as stateful and in-memory.
- Call `Close()` when a session is no longer needed; it zeros key material held by the session.
- Do not use a session after `Close()` returns.
- Sessions are not goroutine-safe. Use one goroutine per session or protect access with external locking.
- This library does not define a stable wire or persistence format. Store the exported message/header fields using your application's own encoding.
- For persistent sessions, serialize state only into a secure store and restore it carefully. Session fields contain live key material.

## Out-of-Order Messages

The Double Ratchet modes support delayed message recovery by storing skipped message keys up to `Config.MaxSkip`. A skipped key is deleted after successful use, so replaying the same delayed message should fail.

If a message gap exceeds `MaxSkip`, decryption returns `ErrMaxSkipExceeded` to prevent unbounded memory growth.

## SCKA Provider Contract

SPQR and Triple Ratchet depend on `scka.Provider`:

```go
type Provider interface {
	InitAlice(sk []byte) error
	InitBob(sk []byte) error
	Send() (msg []byte, sendingEpoch uint32, outputKey []byte, keyEpoch uint32, err error)
	Receive(msg []byte) (receivingEpoch uint32, outputKey []byte, keyEpoch uint32, err error)
	Snapshot() any
	Restore(snapshot any)
	Close() error
}
```

`Snapshot` must deep-copy all mutable state, including key material. `Restore` must fully roll back to that snapshot. SPQR and Triple Ratchet use this on authentication failure so the session remains usable after rejecting a forged message.

`sckatest.MockSCKA` is a reference/mock implementation for tests. It is not a production post-quantum protocol.

## Public Types

The primary public types are:

- `Session`: base Double Ratchet session.
- `HESession`: Double Ratchet session with encrypted headers.
- `SPQRSession`: Sparse Post-Quantum Ratchet session.
- `TripleRatchetSession`: hybrid EC and SPQR session.
- `Message`: base/HE ciphertext container.
- `EncryptedHeader`: encrypted header bytes for HE mode.
- `SCKAHeader`: SPQR transport header.
- `TripleRatchetMessage`: Triple Ratchet ciphertext and composite header.
- `Config`: runtime configuration shared by all modes.
- `scka.Provider`: SCKA interface used by SPQR and Triple Ratchet.

Although several structs expose protocol state fields, application code should treat session state as sensitive implementation detail unless it is intentionally serializing a session.

## Exported Constants

```go
const (
	RootKeySize    = 32 // bytes
	ChainKeySize   = 32 // bytes
	MessageKeySize = 32 // bytes
	DefaultMaxSkip = 1000
)
```

These are useful when pre-allocating buffers or validating key material sizes.

## Sub-Packages

The root package re-exports everything most applications need. These sub-packages are available for advanced use:

| Package | Import path | Purpose |
|---|---|---|
| `crypto` | `go-doubleratchet/crypto` | X25519 key generation, DH shared secret, header encryption primitives (`HENCRYPT`/`HDECRYPT`). |
| `kdf` | `go-doubleratchet/kdf` | Chain KDF, root KDF, HE root KDF, SPQR KDF functions. |
| `scka` | `go-doubleratchet/scka` | `Provider` interface for post-quantum SCKA implementations. |
| `scka/testing` | `go-doubleratchet/scka/testing` | `MockSCKA` test/example implementation. Not for production. |

Full API documentation: [pkg.go.dev/github.com/KushnerykPavel/go-doubleratchet](https://pkg.go.dev/github.com/KushnerykPavel/go-doubleratchet)

## Security Notes

- Use a fresh high-entropy shared secret from a real authenticated handshake.
- Validate peer identity and handshake transcript outside this library.
- Keep associated data stable and identical on both sides.
- Never reuse the same session state for multiple independent conversations.
- Use separate `scka.Provider` instances for Alice and Bob.
- Replace `sckatest.MockSCKA` with a real post-quantum SCKA implementation before production use.
- `Close()` reduces key lifetime in memory but cannot guarantee complete process-wide secret erasure under all Go runtime conditions.

To report a vulnerability, see [SECURITY.md](SECURITY.md).

## Runnable Examples

The repository includes testable examples for all four protocol variants:

```sh
go test -run Example -v
```

This runs `ExampleInitAlice`, `ExampleInitAliceHE`, `ExampleInitAliceSCKA`, and `ExampleInitAliceTripleRatchet` from [`example_test.go`](example_test.go).

## Protocol Specs

Development specs and deeper protocol notes live under:

| Spec | Protocol |
|---|---|
| [`specs/001-double-ratchet-go-library/`](specs/001-double-ratchet-go-library/) | Base Double Ratchet |
| [`specs/002-header-encryption/`](specs/002-header-encryption/) | Header Encryption |
| [`specs/003-sparse-pq-ratchet/`](specs/003-sparse-pq-ratchet/) | Sparse Post-Quantum Ratchet |
| [`specs/004-triple-ratchet/`](specs/004-triple-ratchet/) | Triple Ratchet |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, testing, and PR guidelines.

## License

[MIT](LICENSE)
