package contract

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"strings"
	"time"
)

// EncodeActivationRequestCBOR serializes the v1 fixed-field activation request.
func EncodeActivationRequestCBOR(request ActivationRequest) ([]byte, error) {
	if request.FormatVersion != FormatVersionV1 || request.HardwareID == "" || request.RecipientKeyID == "" || request.RecipientPublicKey == "" {
		return nil, ErrMalformedLicense
	}
	publicKey, err := base64.RawURLEncoding.DecodeString(request.RecipientPublicKey)
	if err != nil || len(publicKey) != 32 {
		return nil, ErrMalformedLicense
	}
	var out bytes.Buffer
	out.WriteByte(0x86)
	writeCBORText(&out, request.FormatVersion)
	writeCBORText(&out, request.RequestID)
	writeCBORText(&out, request.HardwareID)
	writeCBORText(&out, request.RecipientKeyID)
	writeCBORBytes(&out, publicKey)
	writeCBORInt(&out, request.CreatedAt.UTC().Unix())
	return out.Bytes(), nil
}

// DecodeActivationRequestCBOR decodes and validates a v1 activation request.
func DecodeActivationRequestCBOR(raw []byte) (ActivationRequest, error) {
	if len(raw) == 0 || raw[0] != 0x86 {
		return ActivationRequest{}, ErrMalformedLicense
	}
	offset := 1
	version, err := readCBORText(raw, &offset)
	if err != nil {
		return ActivationRequest{}, ErrMalformedLicense
	}
	requestID, err := readCBORText(raw, &offset)
	if err != nil {
		return ActivationRequest{}, ErrMalformedLicense
	}
	hardwareID, err := readCBORText(raw, &offset)
	if err != nil {
		return ActivationRequest{}, ErrMalformedLicense
	}
	recipientKeyID, err := readCBORText(raw, &offset)
	if err != nil {
		return ActivationRequest{}, ErrMalformedLicense
	}
	publicKey, err := readCBORBytes(raw, &offset)
	if err != nil || len(publicKey) != 32 {
		return ActivationRequest{}, ErrMalformedLicense
	}
	createdUnix, err := readCBORInt(raw, &offset)
	if err != nil || offset != len(raw) || version != FormatVersionV1 || hardwareID == "" || recipientKeyID == "" {
		return ActivationRequest{}, ErrMalformedLicense
	}
	return ActivationRequest{FormatVersion: version, RequestID: requestID, HardwareID: hardwareID, RecipientKeyID: recipientKeyID, RecipientPublicKey: base64.RawURLEncoding.EncodeToString(publicKey), CreatedAt: time.Unix(createdUnix, 0).UTC()}, nil
}

// EncodeActivationRequestToken wraps an encoded activation request in act. form.
func EncodeActivationRequestToken(request ActivationRequest) ([]byte, error) {
	raw, err := EncodeActivationRequestCBOR(request)
	if err != nil {
		return nil, err
	}
	return []byte(base64.RawURLEncoding.EncodeToString(raw)), nil
}

// ParseActivationRequestToken parses the external act. representation.
func ParseActivationRequestToken(token []byte) (ActivationRequest, error) {
	value := strings.TrimSpace(string(token))
	strict := base64.RawURLEncoding.Strict()
	raw, err := strict.DecodeString(value)
	if err != nil || strict.EncodeToString(raw) != value {
		return ActivationRequest{}, ErrMalformedLicense
	}
	return DecodeActivationRequestCBOR(raw)
}

func writeCBORText(out *bytes.Buffer, value string) {
	writeCBORHeader(out, 3, len(value))
	out.WriteString(value)
}
func writeCBORBytes(out *bytes.Buffer, value []byte) {
	writeCBORHeader(out, 2, len(value))
	out.Write(value)
}
func writeCBORInt(out *bytes.Buffer, value int64) {
	if value < 0 {
		out.WriteByte(0x3b)
		_ = binary.Write(out, binary.BigEndian, uint64(-1-value))
		return
	}
	if value < 24 {
		out.WriteByte(byte(value))
		return
	}
	out.WriteByte(0x1b)
	_ = binary.Write(out, binary.BigEndian, uint64(value))
}
func writeCBORHeader(out *bytes.Buffer, major, length int) {
	if length < 24 {
		out.WriteByte(byte(major<<5 | length))
		return
	}
	out.WriteByte(byte(major<<5 | 24))
	out.WriteByte(byte(length))
}
func readCBORText(raw []byte, offset *int) (string, error) {
	b, err := readCBOR(raw, offset, 3)
	return string(b), err
}
func readCBORBytes(raw []byte, offset *int) ([]byte, error) { return readCBOR(raw, offset, 2) }
func readCBORInt(raw []byte, offset *int) (int64, error) {
	if *offset >= len(raw) {
		return 0, ErrMalformedLicense
	}
	head := raw[*offset]
	(*offset)++
	major := head >> 5
	n, err := readCBORLength(raw, offset, head&31)
	if err != nil {
		return 0, err
	}
	if major == 0 {
		return int64(n), nil
	}
	if major == 1 {
		return -1 - int64(n), nil
	}
	return 0, ErrMalformedLicense
}
func readCBOR(raw []byte, offset *int, expected byte) ([]byte, error) {
	if *offset >= len(raw) {
		return nil, ErrMalformedLicense
	}
	head := raw[*offset]
	(*offset)++
	if head>>5 != expected {
		return nil, ErrMalformedLicense
	}
	n, err := readCBORLength(raw, offset, head&31)
	if err != nil || n > len(raw)-*offset {
		return nil, ErrMalformedLicense
	}
	value := raw[*offset : *offset+n]
	*offset += n
	return value, nil
}
func readCBORLength(raw []byte, offset *int, additional byte) (int, error) {
	if additional < 24 {
		return int(additional), nil
	}
	if additional == 24 {
		if *offset >= len(raw) {
			return 0, ErrMalformedLicense
		}
		n := int(raw[*offset])
		(*offset)++
		return n, nil
	}
	if additional == 27 && len(raw)-*offset >= 8 {
		n := binary.BigEndian.Uint64(raw[*offset : *offset+8])
		*offset += 8
		if n > uint64(^uint(0)>>1) {
			return 0, ErrMalformedLicense
		}
		return int(n), nil
	}
	return 0, ErrMalformedLicense
}
