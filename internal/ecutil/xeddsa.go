package ecutil

import (
	"crypto/rand"
	"crypto/sha512"
	"io"

	"filippo.io/edwards25519"
	"filippo.io/edwards25519/field"
)

// xeddsaHashPrefix is [0xFE, 0xFF×31] used to domain-separate the nonce hash
// from the challenge hash.
var xeddsaHashPrefix = [32]byte{
	0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
}

// XEdDSASign signs message using the X25519 private key xPriv (must be clamped).
func XEdDSASign(xPriv [32]byte, message []byte) ([64]byte, error) {
	var padded [64]byte
	copy(padded[:], xPriv[:])
	a, err := edwards25519.NewScalar().SetUniformBytes(padded[:])
	if err != nil {
		return [64]byte{}, err
	}

	edPub := new(edwards25519.Point).ScalarBaseMult(a)
	edPubBytes := edPub.Bytes()
	signBit := edPubBytes[31] & 0x80

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

	R := new(edwards25519.Point).ScalarBaseMult(r)
	rBytes := R.Bytes()

	h2 := sha512.New()
	h2.Write(rBytes)
	h2.Write(edPubBytes)
	h2.Write(message)
	hScalar, err := edwards25519.NewScalar().SetUniformBytes(h2.Sum(nil))
	if err != nil {
		return [64]byte{}, err
	}

	s := edwards25519.NewScalar().MultiplyAdd(hScalar, a, r)

	var sig [64]byte
	copy(sig[:32], rBytes)
	copy(sig[32:], s.Bytes())
	sig[63] = (sig[63] & 0x7F) | signBit
	return sig, nil
}

// XEdDSAVerify verifies an XEdDSA signature over message using X25519 public key xPub.
func XEdDSAVerify(xPub [32]byte, message []byte, sig [64]byte) bool {
	signBit := (sig[63] & 0x80) >> 7

	yBytes := MontgomeryUToEdwardsYBytes(xPub)
	if yBytes == nil {
		return false
	}
	yBytes[31] = (yBytes[31] & 0x7F) | (signBit << 7)
	A, err := new(edwards25519.Point).SetBytes(yBytes)
	if err != nil {
		return false
	}

	var rBytes [32]byte
	copy(rBytes[:], sig[:32])
	_, err = new(edwards25519.Point).SetBytes(rBytes[:])
	if err != nil {
		return false
	}

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

	h := sha512.New()
	h.Write(rBytes[:])
	h.Write(A.Bytes())
	h.Write(message)
	hScalar, err := edwards25519.NewScalar().SetUniformBytes(h.Sum(nil))
	if err != nil {
		return false
	}

	minusA := new(edwards25519.Point).Negate(A)
	rCheck := new(edwards25519.Point).VarTimeDoubleScalarBaseMult(hScalar, minusA, sScalar)

	rCheckBytes := rCheck.Bytes()
	var diff byte
	for i := range 32 {
		diff |= rCheckBytes[i] ^ rBytes[i]
	}
	return diff == 0
}

// MontgomeryUToEdwardsYBytes converts a Curve25519 Montgomery u-coordinate to
// the 32-byte little-endian encoding of the Edwards y-coordinate via
// y = (u − 1) · (u + 1)⁻¹ mod p.
func MontgomeryUToEdwardsYBytes(u [32]byte) []byte {
	uElem, err := new(field.Element).SetBytes(u[:])
	if err != nil {
		return nil
	}
	one := new(field.Element).One()
	uMinus1 := new(field.Element).Subtract(uElem, one)
	uPlus1 := new(field.Element).Add(uElem, one)

	zero := new(field.Element)
	if uPlus1.Equal(zero) == 1 {
		return nil
	}

	uPlus1Inv := new(field.Element).Invert(uPlus1)
	y := new(field.Element).Multiply(uMinus1, uPlus1Inv)

	yBytes := y.Bytes()
	return yBytes
}
