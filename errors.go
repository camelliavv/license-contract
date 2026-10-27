package contract

import "errors"

var (
	ErrMalformedLicense     = errors.New("malformed license")
	ErrInvalidSignature     = errors.New("invalid license signature")
	ErrUnsupportedFormat    = errors.New("unsupported license format")
	ErrNotYetValid          = errors.New("license is not yet valid")
	ErrExpired              = errors.New("license is expired")
	ErrRecipientKeyRequired = errors.New("recipient encryption key is required")
	ErrInvalidEncryption    = errors.New("invalid license encryption")
)
