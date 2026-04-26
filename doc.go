// Package doubleratchet implements the Signal Double Ratchet Algorithm
// and its extensions: header encryption (spec §4), sparse post-quantum
// ratchet (SPQR), and triple ratchet (hybrid EC + PQ).
//
// Four session types are provided:
//   - [Session]: Base Double Ratchet (EC only)
//   - [HESession]: Double Ratchet with header encryption
//   - [SPQRSession]: Sparse Post-Quantum Ratchet
//   - [TripleRatchetSession]: Hybrid EC + PQ triple ratchet
//
// Use the corresponding Init*Initiator / Init*Responder constructors to create sessions.
// All sessions implement [io.Closer] for secure key material deletion.
//
// Specification: https://signal.org/docs/specifications/doubleratchet/
package doubleratchet
