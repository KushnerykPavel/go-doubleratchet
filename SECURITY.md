# Security Policy

## Supported Versions

| Version | Supported |
| ------- | --------- |
| latest (main) | ✅ |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Report vulnerabilities privately via [GitHub Security Advisories](https://github.com/KushnerykPavel/go-doubleratchet/security/advisories/new).

Include:
- Description of the vulnerability and affected component
- Steps to reproduce or proof-of-concept
- Potential impact (key compromise, authentication bypass, etc.)
- Suggested fix if you have one

You will receive acknowledgement within 72 hours. Confirmed vulnerabilities will be patched and disclosed publicly following responsible disclosure practices (typically within 90 days or sooner).

## Cryptographic Scope

This library implements the [Signal Double Ratchet specification](https://signal.org/docs/specifications/doubleratchet/). Security issues in scope include:

- Forward secrecy violations
- Break-in recovery failures
- Authentication bypass (AEAD forgery)
- Key material leakage or improper zeroing
- Protocol state machine violations
- Post-quantum ratchet (SPQR/Triple Ratchet) epoch integrity issues

Out of scope: vulnerabilities in underlying primitives (X25519, AES-CBC, HMAC-SHA256) — report those to the Go standard library or `golang.org/x/crypto` maintainers.

## Security Properties

- **Forward secrecy**: Compromise of current keys does not expose past messages.
- **Break-in recovery**: After a DH ratchet step, the session recovers security even if state was compromised.
- **Header protection** (HESession): Message headers are encrypted, hiding session membership and message ordering.
- **Post-quantum resistance** (SPQRSession, TripleRatchetSession): Requires compromise of both elliptic-curve and post-quantum assumptions to decrypt messages.
- **Key erasure**: Superseded key material is zeroed before replacement (§8.1). Call `Close()` when done.
