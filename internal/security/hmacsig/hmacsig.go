package hmacsig

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"time"
)

// BuildMessage is the exact byte sequence we sign/verify:
//
//	X-Timestamp + "\n" + rawBody
func BuildMessage(ts string, body []byte) []byte {
	msg := make([]byte, 0, len(ts)+1+len(body))
	msg = append(msg, ts...)
	msg = append(msg, '\n')
	msg = append(msg, body...)
	return msg
}

// Compute returns "sha256=<hex>" header value for a given secret/timestamp/body.
func Compute(secret []byte, ts string, body []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write(BuildMessage(ts, body))
	sum := mac.Sum(nil)
	dst := make([]byte, len("sha256=")+hex.EncodedLen(len(sum)))
	copy(dst, "sha256=")
	hex.Encode(dst[len("sha256="):], sum)
	return string(dst)
}

// Verify checks the signature and timestamp freshness.
// It expects sig like "sha256=<hex>" and ts as a Unix seconds string.
func Verify(secret []byte, ts, sig string, body []byte, maxSkew time.Duration) error {
	if !strings.HasPrefix(sig, "sha256=") {
		return errors.New("bad sig scheme")
	}
	want, err := hex.DecodeString(sig[len("sha256="):])
	if err != nil || len(want) != sha256.Size {
		return errors.New("bad sig hex")
	}

	// timestamp freshness
	sec, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return errors.New("bad timestamp")
	}
	now := time.Now().Unix()
	if delta := time.Duration(abs64(now-sec)) * time.Second; delta > maxSkew {
		return errors.New("timestamp expired")
	}

	// recompute
	mac := hmac.New(sha256.New, secret)
	mac.Write(BuildMessage(ts, body))
	got := mac.Sum(nil)

	if subtle.ConstantTimeCompare(want, got) != 1 {
		return errors.New("signature mismatch")
	}
	return nil
}

func abs64(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
}
