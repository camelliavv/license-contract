# license-contract

`license-contract` is a small Go package that defines the public data types and
encoding helpers used by a license protocol.

It is intentionally limited to the contract layer. It does not contain private
keys, key storage, signing services, encryption workflows, or business policy.

## Installation

```bash
go get github.com/camelliavv/license-contract
```

```go
import contract "github.com/camelliavv/license-contract"
```

The module requires Go 1.20 or newer.

## What it provides

The package exposes four protocol types:

- `LicensePayload` — license claims and validity information.
- `LicenseEnvelope` — the encoded outer license container.
- `SigningKeyCertificate` — signing-key certificate data.
- `ActivationRequest` — activation request data.

It also provides helpers for:

- deterministic payload and envelope serialization;
- authenticated-data construction with `EnvelopeAAD`;
- activation-request CBOR encoding and decoding;
- license and activation token encoding and parsing;
- strict, unpadded Base64URL encoding;
- shared protocol error values.

## Version and algorithm identifiers

The current protocol identifiers are exported as constants:

```go
contract.FormatVersionV1
contract.EnvelopeFormatVersionV1
contract.SignatureAlgorithm
contract.EncryptionAlgorithm
```

Treat these values as part of the wire contract. Changes can affect token
compatibility.

## Encoding behavior

`EncodeBase64URL` and `DecodeBase64URL` use strict, unpadded Base64URL.
`EncodeLicenseToken` and `EncodeActivationRequestToken` return token bodies; the
package does not add transport-specific prefixes.

Activation requests use the package's fixed v1 CBOR representation:

```go
raw, err := contract.EncodeActivationRequestCBOR(request)
request, err := contract.DecodeActivationRequestCBOR(raw)

token, err := contract.EncodeActivationRequestToken(request)
request, err = contract.ParseActivationRequestToken(token)
```

License token bodies wrap an envelope JSON value:

```go
token := contract.EncodeLicenseToken(envelopeJSON)
envelopeJSON, err := contract.DecodeLicenseToken(token)
```

`CanonicalPayload` and `CanonicalEnvelope` must be used whenever bytes are
signed, encrypted, or compared. They make the relevant serialization stable
across implementations. `EnvelopeAAD` returns the associated data required by
the envelope protocol.

## Minimal example

```go
package main

import (
    "time"

    contract "github.com/camelliavv/license-contract"
)

func main() {
    now := time.Now().UTC().Round(0)
    payload := contract.LicensePayload{
        FormatVersion: contract.FormatVersionV1,
        LicenseID:     "license-example",
        IssuedAt:      now,
        Issuer:        "example",
        Audience:      "example",
        Product:       "example",
        HardwareID:    "hardware-example",
        Features:      []string{"read", "write"},
        NotBefore:     now,
        ExpiresAt:     now.Add(24 * time.Hour),
        KeyID:         "key-example",
    }

    canonical, err := contract.CanonicalPayload(payload)
    if err != nil {
        panic(err)
    }
    _ = canonical
}
```

`CanonicalPayload` normalizes time values, validates required fields, and sorts
feature names before returning JSON bytes. It does not deduplicate features.

## Errors

The package exports protocol errors that can be matched with `errors.Is`:

- `ErrMalformedLicense`
- `ErrInvalidSignature`
- `ErrUnsupportedFormat`
- `ErrNotYetValid`
- `ErrExpired`
- `ErrRecipientKeyRequired`
- `ErrInvalidEncryption`

Use the error values rather than matching error strings.

## Development

Run the package checks from this directory:

```bash
go test ./...
go vet ./...
```

Changes to public types, serialization, or token encoding should include
compatibility tests and a review of their effect on existing data.
