// Package contract contains the wire-level license protocol shared by the
// customer runtime and the vendor issuer. It intentionally contains no
// private-key handling or issuance policy.
package contract

import "time"

const (
	FormatVersionV1         = "v1"
	EnvelopeFormatVersionV1 = "v1"
	SignatureAlgorithm      = "Ed25519"
	EncryptionAlgorithm     = "X25519+HKDF-SHA256+AES-256-GCM"
)

// LicensePayload is the authenticated, encrypted license payload.
type LicensePayload struct {
	FormatVersion string            `json:"format_version"`
	LicenseID     string            `json:"license_id"`
	IssuedAt      time.Time         `json:"issued_at"`
	Issuer        string            `json:"issuer"`
	Audience      string            `json:"audience"`
	Product       string            `json:"product"`
	HardwareID    string            `json:"hardware_id,omitempty"`
	Features      []string          `json:"features,omitempty"`
	Limits        map[string]uint64 `json:"limits,omitempty"`
	NotBefore     time.Time         `json:"not_before"`
	ExpiresAt     time.Time         `json:"expires_at"`
	KeyID         string            `json:"key_id"`
}

// LicenseEnvelope is the signed outer license envelope.
type LicenseEnvelope struct {
	EnvelopeVersion     string `json:"envelope_version"`
	SignatureAlgorithm  string `json:"signature_algorithm"`
	EncryptionAlgorithm string `json:"encryption_algorithm"`
	KeyID               string `json:"key_id"`
	SigningCertificate  string `json:"signing_certificate"`
	RecipientKeyID      string `json:"recipient_key_id"`
	EphemeralPublicKey  string `json:"ephemeral_public_key"`
	Nonce               string `json:"nonce"`
	Ciphertext          string `json:"ciphertext"`
	Signature           string `json:"signature"`
}

// SigningKeyCertificate binds an issuer signing key to a product and audience.
type SigningKeyCertificate struct {
	FormatVersion string    `json:"format_version"`
	RootKeyID     string    `json:"root_key_id"`
	KeyID         string    `json:"key_id"`
	Issuer        string    `json:"issuer"`
	Audience      string    `json:"audience"`
	Product       string    `json:"product"`
	PublicKey     string    `json:"public_key"`
	NotBefore     time.Time `json:"not_before,omitempty"`
	ExpiresAt     time.Time `json:"expires_at,omitempty"`
	Signature     string    `json:"signature"`
}

// ActivationRequest is the client-generated request sent to the issuer.
type ActivationRequest struct {
	FormatVersion      string    `json:"format_version"`
	RequestID          string    `json:"request_id"`
	HardwareID         string    `json:"hardware_id"`
	RecipientKeyID     string    `json:"recipient_key_id"`
	RecipientPublicKey string    `json:"recipient_public_key"`
	CreatedAt          time.Time `json:"created_at"`
}
