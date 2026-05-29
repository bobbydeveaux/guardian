// Package main — Guardian GitHub Marketplace billing webhook.
//
// signature.go isolates the X-Hub-Signature-256 verification logic so it
// can be tested without spinning up an HTTP server.
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
)

// errBadSignature is returned by verifySignature when the supplied
// X-Hub-Signature-256 header does not match the body for the given secret.
// Callers should treat this as a 400 — never log the digest itself.
var errBadSignature = errors.New("signature verification failed")

// errMalformedSignature is returned when the header does not look like
// "sha256=<64 hex chars>". Distinct from errBadSignature so the handler
// can return a precise 400 reason.
var errMalformedSignature = errors.New("malformed X-Hub-Signature-256 header")

// verifySignature checks that header matches HMAC-SHA256(secret, body) in
// the format GitHub Marketplace uses: "sha256=<hex>". Constant-time compare
// via hmac.Equal prevents timing attacks on the digest.
//
// Returns nil on success, errMalformedSignature on a missing prefix or
// invalid hex, errBadSignature on a mismatch.
func verifySignature(secret, body []byte, header string) error {
	const prefix = "sha256="
	if !strings.HasPrefix(header, prefix) {
		return errMalformedSignature
	}
	sigHex := strings.TrimPrefix(header, prefix)
	supplied, err := hex.DecodeString(sigHex)
	if err != nil {
		return errMalformedSignature
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	expected := mac.Sum(nil)
	if !hmac.Equal(expected, supplied) {
		return errBadSignature
	}
	return nil
}
