package contract

import (
	"bytes"
	"testing"
	"time"
)

func TestActivationTokenRoundTrip(t *testing.T) {
	request := ActivationRequest{
		FormatVersion:      FormatVersionV1,
		RequestID:          "request-1",
		HardwareID:         "hw-1",
		RecipientKeyID:     "enc-1",
		RecipientPublicKey: EncodeBase64URL(bytes.Repeat([]byte{7}, 32)),
		CreatedAt:          time.Unix(1700000000, 0).UTC(),
	}
	token, err := EncodeActivationRequestToken(request)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := ParseActivationRequestToken(token)
	if err != nil {
		t.Fatal(err)
	}
	if decoded != request {
		t.Fatalf("round trip mismatch: got %#v want %#v", decoded, request)
	}
}

func TestCanonicalPayloadSortsFeatures(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	payload := LicensePayload{LicenseID: "lic-1", IssuedAt: now, Issuer: "vendor", Audience: "customer", Product: "product", HardwareID: "hw", Features: []string{"write", "read"}, NotBefore: now, ExpiresAt: now.Add(time.Hour), KeyID: "key-1"}
	canonical, err := CanonicalPayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(canonical, []byte(`"features":["read","write"]`)) {
		t.Fatalf("features were not canonicalized: %s", canonical)
	}
}

func TestCanonicalPayloadRejectsDuplicateFeatures(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	payload := LicensePayload{
		LicenseID: "lic-1", IssuedAt: now, Issuer: "vendor", Audience: "customer",
		Product: "product", HardwareID: "hw", Features: []string{"read", "read"},
		NotBefore: now, ExpiresAt: now.Add(time.Hour), KeyID: "key-1",
	}
	if _, err := CanonicalPayload(payload); err == nil {
		t.Fatal("duplicate features were accepted")
	}
}

func TestCanonicalPayloadRejectsInvalidLimitKey(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	payload := LicensePayload{
		LicenseID: "lic-1", IssuedAt: now, Issuer: "vendor", Audience: "customer",
		Product: "product", HardwareID: "hw", Limits: map[string]uint64{" users.total": 1},
		NotBefore: now, ExpiresAt: now.Add(time.Hour), KeyID: "key-1",
	}
	if _, err := CanonicalPayload(payload); err == nil {
		t.Fatal("invalid limit key was accepted")
	}
}
