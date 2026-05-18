package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
)

func sign(secret, body []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func TestVerifySignatureAcceptsMatchingDigest(t *testing.T) {
	secret := []byte("test-secret")
	body := []byte(`{"action":"purchased"}`)
	header := sign(secret, body)

	if err := verifySignature(secret, body, header); err != nil {
		t.Fatalf("verifySignature returned %v, want nil", err)
	}
}

func TestVerifySignatureRejectsMismatchedDigest(t *testing.T) {
	secret := []byte("test-secret")
	body := []byte(`{"action":"purchased"}`)
	// Sign with a different secret to produce a mismatching but well-formed
	// digest, then ask verifySignature to check it under the real secret.
	header := sign([]byte("wrong-secret"), body)

	err := verifySignature(secret, body, header)
	if !errors.Is(err, errBadSignature) {
		t.Fatalf("verifySignature returned %v, want errBadSignature", err)
	}
}

func TestVerifySignatureRejectsMissingPrefix(t *testing.T) {
	secret := []byte("test-secret")
	body := []byte(`{"action":"purchased"}`)
	header := sign(secret, body)
	// Strip the "sha256=" prefix to simulate a sender that uses the wrong
	// header layout (e.g. the legacy X-Hub-Signature SHA-1 format).
	headerNoPrefix := header[len("sha256="):]

	err := verifySignature(secret, body, headerNoPrefix)
	if !errors.Is(err, errMalformedSignature) {
		t.Fatalf("verifySignature returned %v, want errMalformedSignature", err)
	}
}

func TestVerifySignatureRejectsNonHexDigest(t *testing.T) {
	secret := []byte("test-secret")
	body := []byte(`{"action":"purchased"}`)

	err := verifySignature(secret, body, "sha256=not-actually-hex-zz")
	if !errors.Is(err, errMalformedSignature) {
		t.Fatalf("verifySignature returned %v, want errMalformedSignature", err)
	}
}

func TestVerifySignatureRejectsEmptyHeader(t *testing.T) {
	err := verifySignature([]byte("secret"), []byte("body"), "")
	if !errors.Is(err, errMalformedSignature) {
		t.Fatalf("verifySignature returned %v, want errMalformedSignature", err)
	}
}

func TestVerifySignatureIsBodySensitive(t *testing.T) {
	secret := []byte("test-secret")
	signed := []byte(`{"action":"purchased"}`)
	header := sign(secret, signed)
	tampered := []byte(`{"action":"cancelled"}`)

	err := verifySignature(secret, tampered, header)
	if !errors.Is(err, errBadSignature) {
		t.Fatalf("verifySignature on tampered body returned %v, want errBadSignature", err)
	}
}
