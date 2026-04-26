package crypto

// ZeroBytes overwrites a byte slice with zeros to scrub sensitive key material.
func ZeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
