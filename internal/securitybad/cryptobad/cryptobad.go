package cryptobad

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"  // bad choice on purpose
	"crypto/sha1" // bad choice on purpose
	"encoding/hex"
)

// StorePlain just returns the password "as stored" (plaintext).
func StorePlain(password string) string {
	return password
}

// HashSHA1 returns a fast, unsalted SHA-1 digest (do not use in real systems).
func HashSHA1(password string) string {
	sum := sha1.Sum([]byte(password))
	return hex.EncodeToString(sum[:])
}

// HashMD5 returns an MD5 digest (also bad; collision-prone).
func HashMD5(s string) string {
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

// InsecureEncryptGCMFixedNonce uses AES-GCM with a fixed all-zero nonce.
// Reusing a nonce with GCM is catastrophic (forged messages, plaintext leaks).
// Returned value is ciphertext; nonce is implicit (always zeros).
func InsecureEncryptGCMFixedNonce(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize()) // zeros every time
	return gcm.Seal(nil, nonce, plaintext, nil), nil
}
