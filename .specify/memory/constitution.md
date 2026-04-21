# Go Double Ratchet Constitution

## Core Principles

### I. Spec-Driven Delivery
Every substantial change MUST begin with Speckit artifacts that define scope, user value, constraints, and acceptance criteria before code generation starts. Planning documents are part of the deliverable, not optional scaffolding.

### II. Library-First API Design
This repository exists to produce a reusable Go library. Public APIs MUST be typed, documented, and minimally opinionated. Wire format, transport, persistence, and application-specific session management MUST remain outside the core library unless a spec explicitly expands scope.

### III. Crypto Conformance Before Convenience
Protocol behavior MUST track the Signal Double Ratchet specification for the in-scope variant. Cryptographic primitives, state transitions, skipped-key handling, and failure modes MUST be chosen for spec conformance and safety before ergonomics or abstraction reuse.

### IV. Test the State Machine
Protocol and state-transition work MUST be validated with unit and integration coverage for initialization, send/receive progression, ratchet advancement, out-of-order handling, replay rejection, and bounded skipped-key storage. Tests MUST exercise behavior, not only helper functions.

### V. Minimal Surface, Explicit Extensibility
The initial implementation MUST stay focused on base Double Ratchet functionality. Header encryption, sparse post-quantum ratchets, triple ratchet flows, storage adapters, and transport framing MUST be deferred unless explicitly planned. Extension points MAY be designed, but speculative features MUST NOT leak into the public API.

## Additional Constraints

- Primary language is Go.
- Prefer the Go standard library and narrowly scoped cryptographic dependencies.
- Base Double Ratchet v1 includes section 3 of the Signal specification only.
- Header encryption, SPQR, and Triple Ratchet are explicitly out of scope for v1.
- Secure deletion claims in Go MUST be documented as best-effort only.
- Public APIs MUST expose enough typed structure for callers to serialize messages themselves.

## Workflow & Quality Gates

- Each feature MUST have `spec.md`, `plan.md`, and `tasks.md` under `specs/`.
- Crypto-sensitive plans MUST include `research.md`, `data-model.md`, `contracts/`, and `quickstart.md`.
- A crypto review gate MUST happen before code-generation tasks begin.
- Planning MUST state invariant fields and error behavior for protocol state.
- Tasks MUST be organized so the first user story is a demonstrable MVP.

## Governance

This constitution supersedes ad hoc preferences in this repository. Changes to the constitution require updating dependent templates or plans when those changes alter workflow or quality expectations. Every implementation plan and review should verify compliance with these principles.

**Version**: 1.0.0 | **Ratified**: 2026-04-21 | **Last Amended**: 2026-04-21
