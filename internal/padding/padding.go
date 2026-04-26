// Package padding implements PKCS#7 padding and unpadding.
package padding

import "errors"

var (
	errEmptyData         = errors.New("empty data")
	errInvalidBlockSize  = errors.New("invalid block size")
	errInvalidPadding    = errors.New("invalid padding")
	errInvalidPaddingVal = errors.New("invalid padding value")
)

// PKCS7Pad appends PKCS#7 padding to data to align it to blockSize.
func PKCS7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)
	pad := make([]byte, padding)
	for i := range pad {
		pad[i] = byte(padding)
	}
	return append(data, pad...)
}

// PKCS7Unpad removes PKCS#7 padding from data, returning an error if padding is invalid.
func PKCS7Unpad(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 {
		return nil, errEmptyData
	}
	if len(data)%blockSize != 0 {
		return nil, errInvalidBlockSize
	}
	padding := int(data[len(data)-1])
	if padding == 0 || padding > blockSize {
		return nil, errInvalidPadding
	}
	for i := len(data) - padding; i < len(data); i++ {
		if data[i] != byte(padding) {
			return nil, errInvalidPaddingVal
		}
	}
	return data[:len(data)-padding], nil
}
