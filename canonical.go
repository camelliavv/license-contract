package contract

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

var b64 = base64.RawURLEncoding.Strict()

// CanonicalPayload validates and serializes a payload deterministically.
func CanonicalPayload(payload LicensePayload) ([]byte, error) {
	if payload.FormatVersion == "" {
		payload.FormatVersion = FormatVersionV1
	}
	if payload.IssuedAt.IsZero() {
		return nil, fmt.Errorf("%w: issued_at is required", ErrMalformedLicense)
	}
	if payload.NotBefore.IsZero() || payload.ExpiresAt.IsZero() {
		return nil, fmt.Errorf("%w: validity interval is required", ErrMalformedLicense)
	}
	if payload.ExpiresAt.Before(payload.NotBefore) {
		return nil, fmt.Errorf("%w: expires_at precedes not_before", ErrMalformedLicense)
	}
	if strings.TrimSpace(payload.LicenseID) == "" || strings.TrimSpace(payload.Issuer) == "" ||
		strings.TrimSpace(payload.Audience) == "" || strings.TrimSpace(payload.Product) == "" ||
		strings.TrimSpace(payload.HardwareID) == "" || strings.TrimSpace(payload.KeyID) == "" {
		return nil, fmt.Errorf("%w: required field is empty", ErrMalformedLicense)
	}
	payload.Features = append([]string(nil), payload.Features...)
	for i := range payload.Features {
		payload.Features[i] = strings.TrimSpace(payload.Features[i])
	}
	sort.Strings(payload.Features)
	if payload.Limits != nil {
		copyLimits := make(map[string]uint64, len(payload.Limits))
		for key, value := range payload.Limits {
			copyLimits[key] = value
		}
		payload.Limits = copyLimits
	}
	payload.NotBefore = payload.NotBefore.UTC().Round(0)
	payload.ExpiresAt = payload.ExpiresAt.UTC().Round(0)
	payload.IssuedAt = payload.IssuedAt.UTC().Round(0)
	return json.Marshal(payload)
}

type unsignedEnvelope struct {
	EnvelopeVersion     string `json:"envelope_version"`
	SignatureAlgorithm  string `json:"signature_algorithm"`
	EncryptionAlgorithm string `json:"encryption_algorithm"`
	KeyID               string `json:"key_id"`
	SigningCertificate  string `json:"signing_certificate"`
	RecipientKeyID      string `json:"recipient_key_id"`
	EphemeralPublicKey  string `json:"ephemeral_public_key"`
	Nonce               string `json:"nonce"`
	Ciphertext          string `json:"ciphertext"`
}

// CanonicalEnvelope returns the exact bytes covered by an envelope signature.
func CanonicalEnvelope(envelope LicenseEnvelope) ([]byte, error) {
	return json.Marshal(unsignedEnvelope{
		EnvelopeVersion:     envelope.EnvelopeVersion,
		SignatureAlgorithm:  envelope.SignatureAlgorithm,
		EncryptionAlgorithm: envelope.EncryptionAlgorithm,
		KeyID:               envelope.KeyID,
		SigningCertificate:  envelope.SigningCertificate,
		RecipientKeyID:      envelope.RecipientKeyID,
		EphemeralPublicKey:  envelope.EphemeralPublicKey,
		Nonce:               envelope.Nonce,
		Ciphertext:          envelope.Ciphertext,
	})
}

// EnvelopeAAD returns the authenticated associated data for an envelope.
func EnvelopeAAD(envelope LicenseEnvelope) []byte {
	var aad bytes.Buffer
	writeAADField(&aad, "license/envelope/v1")
	writeAADField(&aad, envelope.KeyID)
	writeAADField(&aad, envelope.RecipientKeyID)
	return aad.Bytes()
}

func writeAADField(out *bytes.Buffer, value string) {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(value)))
	_, _ = out.Write(length[:])
	_, _ = out.WriteString(value)
}

// EncodeBase64URL encodes protocol bytes without padding.
func EncodeBase64URL(value []byte) string { return b64.EncodeToString(value) }

// DecodeBase64URL decodes strict, unpadded protocol bytes.
func DecodeBase64URL(value string) ([]byte, error) { return b64.DecodeString(value) }

// EncodeLicenseToken wraps an envelope in the external lic. representation.
func EncodeLicenseToken(envelope []byte) []byte {
	encoded := make([]byte, b64.EncodedLen(len(envelope)))
	b64.Encode(encoded, envelope)
	return encoded
}

// DecodeLicenseToken decodes and validates the external lic. representation.
func DecodeLicenseToken(raw []byte) ([]byte, error) {
	trimmed := strings.TrimSpace(string(raw))
	decoded, err := b64.DecodeString(trimmed)
	if err != nil || len(decoded) == 0 {
		return nil, ErrMalformedLicense
	}
	return decoded, nil
}
