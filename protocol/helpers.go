package protocol

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"uuid"

	"github.com/fxamacker/cbor/v2"
	"github.com/telesma-app/ctap/attestation"
)

func (f AuthDataFlag) UserPresent() bool {
	return f&AuthDataFlagUserPresent != 0
}
func (f AuthDataFlag) UserVerified() bool {
	return f&AuthDataFlagUserVerified != 0
}
func (f AuthDataFlag) AttestedCredentialDataIncluded() bool {
	return f&AuthDataFlagAttestedCredentialDataIncluded != 0
}
func (f AuthDataFlag) ExtensionDataIncluded() bool {
	return f&AuthDataFlagExtensionDataIncluded != 0
}

type authData struct {
	RPIDHash               []byte
	Flags                  AuthDataFlag
	SignCount              uint32
	AttestedCredentialData *AttestedCredentialData
	Extensions             []byte
}

func parseAuthData(data []byte) (authData, error) {
	if len(data) < 37 {
		return authData{}, fmt.Errorf("auth data is too short: got %d bytes, want at least 37", len(data))
	}

	if reserved := AuthDataFlag(data[32]) & ((1 << 1) | (1 << 5)); reserved != 0 {
		return authData{}, fmt.Errorf("auth data uses reserved flag bits 0x%02x", byte(reserved))
	}

	d := authData{
		RPIDHash:  data[:32],
		Flags:     AuthDataFlag(data[32]),
		SignCount: binary.BigEndian.Uint32(data[33:37]),
	}

	offset := 37
	if d.Flags.AttestedCredentialDataIncluded() {
		if len(data) < offset+16 {
			return authData{}, fmt.Errorf("auth data is missing attested credential AAGUID")
		}

		credData := &AttestedCredentialData{
			AAGUID: uuid.UUID(data[offset : offset+16]),
		}
		offset += 16

		// Credential ID
		if len(data) < offset+2 {
			return authData{}, fmt.Errorf("auth data is missing credential ID length")
		}

		length := binary.BigEndian.Uint16(data[offset : offset+2])

		offset += 2
		if len(data) < offset+int(length) {
			return authData{}, fmt.Errorf("auth data credential ID is truncated")
		}

		credData.CredentialID = data[offset : offset+int(length)]
		offset += int(length)

		// Credential Public Key
		if len(data) == offset {
			return authData{}, fmt.Errorf("auth data is missing credential public key")
		}

		dec := cbor.NewDecoder(bytes.NewReader(data[offset:]))
		if err := dec.Decode(&credData.CredentialPublicKey); err != nil {
			return authData{}, err
		}

		offset += dec.NumBytesRead()

		d.AttestedCredentialData = credData
	}

	if d.Flags.ExtensionDataIncluded() {
		if len(data) == offset {
			return authData{}, fmt.Errorf("auth data is missing extension data")
		}

		extensions := data[offset:]
		decoder := cbor.NewDecoder(bytes.NewReader(extensions))

		var values map[string]any
		if err := decoder.Decode(&values); err != nil {
			return authData{}, fmt.Errorf("decode auth data extensions: %w", err)
		}

		if values == nil {
			return authData{}, fmt.Errorf("auth data extension data must be a CBOR map")
		}

		if decoder.NumBytesRead() != len(extensions) {
			return authData{}, fmt.Errorf(
				"auth data extensions have %d trailing bytes",
				len(extensions)-decoder.NumBytesRead(),
			)
		}

		d.Extensions = extensions
		offset = len(data)
	}

	if offset != len(data) {
		return authData{}, fmt.Errorf("auth data has %d trailing bytes", len(data)-offset)
	}

	return d, nil
}

func (vv Versions) Supports(ver Version) bool {
	for _, v := range vv {
		if v == ver {
			return true
		}
	}

	return false
}

func (vv Versions) IsPreviewOnly() bool {
	fidoTwo := false
	fidoTwoOnePre := false
	fidoTwoOne := false
	fidoTwoThree := false

	for _, v := range vv {
		switch v {
		case FIDO_2_0:
			fidoTwo = true
		case FIDO_2_1_PRE:
			fidoTwoOnePre = true
		case FIDO_2_1:
			fidoTwoOne = true
		case FIDO_2_3:
			fidoTwoThree = true
		}
	}

	return fidoTwo && (!fidoTwoOne && !fidoTwoThree && fidoTwoOnePre)
}

func (r *AuthenticatorMakeCredentialResponse) PackedAttestationStatementFormat() (attestation.PackedAttestationStatementFormat, bool) {
	return attestation.ParsePackedStatement(r.AttestationStatement)
}

func (r *AuthenticatorMakeCredentialResponse) FIDOU2FAttestationStatementFormat() (attestation.FIDOU2FAttestationStatementFormat, bool) {
	return attestation.ParseFIDOU2FStatement(r.AttestationStatement)
}

func (r *AuthenticatorMakeCredentialResponse) TPMAttestationStatementFormat() (attestation.TPMAttestationStatementFormat, bool) {
	return attestation.ParseTPMStatement(r.AttestationStatement)
}
