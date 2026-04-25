package x3dh

// XEdDSA sign/verify for X25519 keys.
//
// X25519 keys cannot sign directly; XEdDSA performs a birational map to
// Ed25519 form, signs, and encodes the sign bit of the Edwards public key
// in the most-significant bit of the last signature byte.
//
// Reference: Signal XEdDSA specification https://signal.org/docs/specifications/xeddsa/
// Cross-referenced with libsignal:
//   rust/core/src/curve/curve25519.rs (calculate_signature / verify_signature)

import (
	"crypto/rand"
	"crypto/sha512"
	"io"
	"math/big"

	"filippo.io/edwards25519"
)

// fieldPrime is p = 2^255 - 19, the field prime for Curve25519 / Ed25519.
var fieldPrime = func() *big.Int {
	p := new(big.Int).Lsh(big.NewInt(1), 255)
	p.Sub(p, big.NewInt(19))
	return p
}()

// xeddsaHashPrefix is [0xFE, 0xFF×31] used to domain-separate the nonce hash
// from the challenge hash.
var xeddsaHashPrefix = [32]byte{
	0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
}

// xeddsaSign signs message using the X25519 private key xPriv (must be clamped).
//
// Algorithm (per Signal XEdDSA/Curve25519 spec):
//  1. Interpret the 32-byte clamped key as scalar a (reduced mod l via padding to 64 bytes).
//  2. Compute Ed25519 public key A = a·G; extract sign bit from A.
//  3. Derive nonce r = SHA-512(prefix ‖ xPriv ‖ message ‖ random) reduced mod l.
//  4. R = r·G
//  5. Challenge h = SHA-512(R ‖ A ‖ message) reduced mod l.
//  6. S = h·a + r
//  7. sig = R ‖ S; store sign bit of A in sig[63] MSB.
func xeddsaSign(xPriv [32]byte, message []byte) ([64]byte, error) {
	// Step 1: scalar a = xPriv reduced mod l.
	// Pad to 64 bytes so SetUniformBytes (which reduces a 512-bit LE int mod l)
	// gives the same result as curve25519-dalek's Scalar::from_bytes_mod_order.
	var padded [64]byte
	copy(padded[:], xPriv[:])
	a, err := edwards25519.NewScalar().SetUniformBytes(padded[:])
	if err != nil {
		return [64]byte{}, err
	}

	// Step 2: A = a·G (Edwards public key), extract sign bit.
	edPub := new(edwards25519.Point).ScalarBaseMult(a)
	edPubBytes := edPub.Bytes()
	signBit := edPubBytes[31] & 0x80

	// Step 3: nonce r = SHA-512(prefix ‖ xPriv ‖ message ‖ random) mod l.
	var random [64]byte
	if _, err := io.ReadFull(rand.Reader, random[:]); err != nil {
		return [64]byte{}, err
	}
	h1 := sha512.New()
	h1.Write(xeddsaHashPrefix[:])
	h1.Write(xPriv[:])
	h1.Write(message)
	h1.Write(random[:])
	r, err := edwards25519.NewScalar().SetUniformBytes(h1.Sum(nil))
	if err != nil {
		return [64]byte{}, err
	}

	// Step 4: R = r·G.
	R := new(edwards25519.Point).ScalarBaseMult(r)
	rBytes := R.Bytes()

	// Step 5: challenge h = SHA-512(R ‖ A ‖ message) mod l.
	h2 := sha512.New()
	h2.Write(rBytes)
	h2.Write(edPubBytes)
	h2.Write(message)
	hScalar, err := edwards25519.NewScalar().SetUniformBytes(h2.Sum(nil))
	if err != nil {
		return [64]byte{}, err
	}

	// Step 6: S = h·a + r.
	s := edwards25519.NewScalar().MultiplyAdd(hScalar, a, r)

	// Step 7: assemble sig = R ‖ S; store sign bit in sig[63] MSB.
	var sig [64]byte
	copy(sig[:32], rBytes)
	copy(sig[32:], s.Bytes())
	sig[63] = (sig[63] & 0x7F) | signBit
	return sig, nil
}

// xeddsaVerify verifies an XEdDSA signature over message using X25519 public key xPub.
//
// Algorithm:
//  1. Extract sign bit from sig[63] MSB.
//  2. Convert Montgomery u-coordinate (xPub) to Edwards y = (u−1)·(u+1)⁻¹ mod p,
//     then reconstruct the Edwards point A using the sign bit.
//  3. Decode R from sig[0:32]; decode S from sig[32:64] (sign bit cleared).
//  4. Compute h = SHA-512(R ‖ A ‖ message) mod l.
//  5. Verify: S·G − h·A == R.
func xeddsaVerify(xPub [32]byte, message []byte, sig [64]byte) bool {
	signBit := (sig[63] & 0x80) >> 7

	// Step 2: Montgomery u → Edwards point A.
	yBytes := montgomeryUToEdwardsYBytes(xPub)
	if yBytes == nil {
		return false
	}
	// Set sign bit in the compressed Edwards encoding.
	yBytes[31] = (yBytes[31] & 0x7F) | (signBit << 7)
	A, err := new(edwards25519.Point).SetBytes(yBytes)
	if err != nil {
		return false
	}

	// Step 3: decode R.
	var rBytes [32]byte
	copy(rBytes[:], sig[:32])
	_, err = new(edwards25519.Point).SetBytes(rBytes[:])
	if err != nil {
		return false
	}

	// Decode S with sign bit cleared; reject oversized values early.
	var sBytes [32]byte
	copy(sBytes[:], sig[32:])
	sBytes[31] &= 0x7F
	if sBytes[31]&0xE0 != 0 {
		return false
	}
	sScalar, err := edwards25519.NewScalar().SetCanonicalBytes(sBytes[:])
	if err != nil {
		return false
	}

	// Step 4: h = SHA-512(R ‖ A ‖ message) mod l.
	h := sha512.New()
	h.Write(rBytes[:])
	h.Write(A.Bytes())
	h.Write(message)
	hScalar, err := edwards25519.NewScalar().SetUniformBytes(h.Sum(nil))
	if err != nil {
		return false
	}

	// Step 5: check S·G − h·A == R  (i.e., h·(−A) + S·G == R).
	minusA := new(edwards25519.Point).Negate(A)
	rCheck := new(edwards25519.Point).VarTimeDoubleScalarBaseMult(hScalar, minusA, sScalar)

	// Constant-time comparison.
	rCheckBytes := rCheck.Bytes()
	var diff byte
	for i := range 32 {
		diff |= rCheckBytes[i] ^ rBytes[i]
	}
	return diff == 0
}

// montgomeryUToEdwardsYBytes converts a Curve25519 Montgomery u-coordinate to
// the 32-byte little-endian encoding of the Edwards y-coordinate via
// y = (u − 1) · (u + 1)⁻¹ mod p.
//
// Returns nil if u+1 ≡ 0 (mod p), i.e., u = p−1, which is an invalid key.
func montgomeryUToEdwardsYBytes(u [32]byte) []byte {
	// Convert 32-byte LE to big-endian for math/big.
	uBE := make([]byte, 32)
	for i, b := range u {
		uBE[31-i] = b
	}
	uInt := new(big.Int).SetBytes(uBE)

	one := big.NewInt(1)
	uMinus1 := new(big.Int).Sub(uInt, one)
	uPlus1 := new(big.Int).Add(uInt, one)

	uPlus1Inv := new(big.Int).ModInverse(uPlus1, fieldPrime)
	if uPlus1Inv == nil {
		// u = p−1 → denominator is 0; invalid key.
		return nil
	}

	y := new(big.Int).Mul(uMinus1, uPlus1Inv)
	y.Mod(y, fieldPrime)

	// Encode as 32-byte LE.
	yBE := y.Bytes()
	yLE := make([]byte, 32)
	for i, b := range yBE {
		yLE[len(yBE)-1-i] = b
	}
	return yLE
}
