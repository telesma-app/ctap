package client

import (
	"context"
	"crypto/fips140"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"iter"
	"slices"

	"github.com/fxamacker/cbor/v2"
	"github.com/telesma-app/ctap/attestation"
	"github.com/telesma-app/ctap/cose"
	"github.com/telesma-app/ctap/credential"
	"github.com/telesma-app/ctap/crypto"
	"github.com/telesma-app/ctap/diagnostic"
	"github.com/telesma-app/ctap/internal/fips140policy"
	pinvalidation "github.com/telesma-app/ctap/internal/pin"
	"github.com/telesma-app/ctap/options"
	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
)

// Client sends CTAP commands through a bound transport. Create it with NewClient.
type Client struct {
	diagnosticSink diagnostic.Sink
	encMode        cbor.EncMode
	decMode        cbor.DecMode
	transport      ctaptransport.CBOR
}

// ErrTransportNotConfigured means NewClient received no transport.
var ErrTransportNotConfigured = errors.New("client: transport not configured")

// NewClient borrows the configured transport without performing I/O.
func NewClient(opts ...options.Option) (*Client, error) {
	oo := options.NewOptions(opts...)
	if oo.Transport == nil {
		return nil, ErrTransportNotConfigured
	}

	return &Client{
		diagnosticSink: oo.DiagnosticSink,
		encMode:        oo.EncMode,
		decMode:        oo.DecMode,
		transport:      oo.Transport,
	}, nil
}

func (cl *Client) MakeCredential(
	ctx context.Context,
	pinUvAuthProtocol protocol.PinUvAuthProtocol,
	pinUvAuthToken []byte,
	clientDataHash []byte,
	rp credential.PublicKeyCredentialRpEntity,
	user credential.PublicKeyCredentialUserEntity,
	pubKeyCredParams []credential.PublicKeyCredentialParameters,
	excludeList []credential.PublicKeyCredentialDescriptor,
	extensions *protocol.CreateExtensionInputs,
	options map[protocol.Option]bool,
	enterpriseAttestation uint,
	attestationFormatsPreference []attestation.AttestationStatementFormatIdentifier,
) (protocol.AuthenticatorMakeCredentialResponse, error) {
	if err := validateClientDataHash(clientDataHash); err != nil {
		return protocol.AuthenticatorMakeCredentialResponse{}, err
	}

	pubKeyCredParams, err := fips140policy.FilterCredentialParameters(pubKeyCredParams)
	if err != nil {
		return protocol.AuthenticatorMakeCredentialResponse{}, err
	}

	var requestExtensions protocol.CreateExtensionInputs
	if extensions != nil {
		requestExtensions = *extensions
	}

	previewSignAlgorithms, err := fips140policy.FilterPreviewSignAlgorithms(
		requestExtensions.PreviewSign.Algorithms,
	)
	if err != nil {
		return protocol.AuthenticatorMakeCredentialResponse{}, err
	}

	requestExtensions.PreviewSign.Algorithms = previewSignAlgorithms
	if fips140.Enabled() {
		if err := validateFIPS140HMACSecret(requestExtensions.CreateHMACSecretMCInput.HMACSecret); err != nil {
			return protocol.AuthenticatorMakeCredentialResponse{}, err
		}
	}

	req := &protocol.AuthenticatorMakeCredentialRequest{
		ClientDataHash:               clientDataHash,
		RP:                           rp,
		User:                         user,
		PubKeyCredParams:             pubKeyCredParams,
		ExcludeList:                  excludeList,
		Extensions:                   requestExtensions,
		Options:                      options,
		EnterpriseAttestation:        enterpriseAttestation,
		AttestationFormatsPreference: attestationFormatsPreference,
	}

	if pinUvAuthToken != nil {
		if err := pinvalidation.ValidateUvAuthToken(pinUvAuthProtocol, pinUvAuthToken); err != nil {
			return protocol.AuthenticatorMakeCredentialResponse{}, err
		}

		pinUvAuthParam := crypto.Authenticate(
			pinUvAuthProtocol,
			pinUvAuthToken,
			clientDataHash,
		)

		req.PinUvAuthParam = pinUvAuthParam
		req.PinUvAuthProtocol = pinUvAuthProtocol
	}

	b, err := cl.encMode.Marshal(req)
	if err != nil {
		return protocol.AuthenticatorMakeCredentialResponse{}, fmt.Errorf("cannot marshal MakeCredential CBOR request: %w", err)
	}

	respRaw, err := cl.exchange(ctx, slices.Concat([]byte{byte(protocol.AuthenticatorMakeCredential)}, b))
	if err != nil {
		return protocol.AuthenticatorMakeCredentialResponse{}, err
	}

	var resp protocol.AuthenticatorMakeCredentialResponse
	if err := cl.decMode.Unmarshal(respRaw.Data, &resp); err != nil {
		return protocol.AuthenticatorMakeCredentialResponse{}, err
	}

	authData, err := protocol.ParseMakeCredentialAuthData(resp.AuthDataRaw)
	if err != nil {
		return protocol.AuthenticatorMakeCredentialResponse{}, err
	}

	if authData.AttestedCredentialData != nil {
		if err := fips140policy.ValidateCredentialKey(authData.AttestedCredentialData.CredentialPublicKey); err != nil {
			return protocol.AuthenticatorMakeCredentialResponse{}, err
		}
	}

	resp.AuthData = &authData

	return resp, nil
}

func (cl *Client) GetAssertion(
	ctx context.Context,
	pinUvAuthProtocol protocol.PinUvAuthProtocol,
	pinUvAuthToken []byte,
	rpID string,
	clientDataHash []byte,
	allowList []credential.PublicKeyCredentialDescriptor,
	extensions *protocol.GetExtensionInputs,
	options map[protocol.Option]bool,
) iter.Seq2[protocol.AuthenticatorGetAssertionResponse, error] {
	return func(yield func(protocol.AuthenticatorGetAssertionResponse, error) bool) {
		if err := validateClientDataHash(clientDataHash); err != nil {
			yield(protocol.AuthenticatorGetAssertionResponse{}, err)
			return
		}

		if fips140.Enabled() && extensions != nil {
			if err := validateFIPS140HMACSecret(extensions.HMACSecret); err != nil {
				yield(protocol.AuthenticatorGetAssertionResponse{}, err)
				return
			}
		}

		var requestExtensions protocol.GetExtensionInputs
		if extensions != nil {
			requestExtensions = *extensions
		}

		req := &protocol.AuthenticatorGetAssertionRequest{
			RPID:           rpID,
			ClientDataHash: clientDataHash,
			AllowList:      allowList,
			Extensions:     requestExtensions,
			Options:        options,
		}

		if pinUvAuthToken != nil {
			if err := pinvalidation.ValidateUvAuthToken(pinUvAuthProtocol, pinUvAuthToken); err != nil {
				yield(protocol.AuthenticatorGetAssertionResponse{}, err)
				return
			}

			pinUvAuthParamBegin := crypto.Authenticate(
				pinUvAuthProtocol,
				pinUvAuthToken,
				clientDataHash,
			)

			req.PinUvAuthParam = pinUvAuthParamBegin
			req.PinUvAuthProtocol = pinUvAuthProtocol
		}

		bBegin, err := cl.encMode.Marshal(req)
		if err != nil {
			yield(protocol.AuthenticatorGetAssertionResponse{}, err)
			return
		}

		respRawBegin, err := cl.exchange(ctx, slices.Concat([]byte{byte(protocol.AuthenticatorGetAssertion)}, bBegin))
		if err != nil {
			yield(protocol.AuthenticatorGetAssertionResponse{}, err)
			return
		}

		var respBegin protocol.AuthenticatorGetAssertionResponse
		if err := cl.decMode.Unmarshal(respRawBegin.Data, &respBegin); err != nil {
			yield(protocol.AuthenticatorGetAssertionResponse{}, err)
			return
		}

		authData, err := protocol.ParseGetAssertionAuthData(respBegin.AuthDataRaw)
		if err != nil {
			yield(protocol.AuthenticatorGetAssertionResponse{}, err)
			return
		}

		respBegin.AuthData = &authData

		if !yield(respBegin, nil) {
			return
		}

		if respBegin.NumberOfCredentials == 0 {
			return
		}

		for i := uint(1); i < respBegin.NumberOfCredentials; i++ {
			respRaw, err := cl.exchange(ctx, []byte{byte(protocol.AuthenticatorGetNextAssertion)})
			if err != nil {
				yield(protocol.AuthenticatorGetAssertionResponse{}, err)
				return
			}

			var resp protocol.AuthenticatorGetAssertionResponse
			if err := cl.decMode.Unmarshal(respRaw.Data, &resp); err != nil {
				yield(protocol.AuthenticatorGetAssertionResponse{}, err)
				return
			}

			authData, err := protocol.ParseGetAssertionAuthData(resp.AuthDataRaw)
			if err != nil {
				yield(protocol.AuthenticatorGetAssertionResponse{}, err)
				return
			}

			resp.AuthData = &authData

			if !yield(resp, nil) {
				return
			}
		}
	}
}

func (cl *Client) GetInfo(ctx context.Context) (protocol.AuthenticatorGetInfoResponse, error) {
	respRaw, err := cl.exchange(ctx, []byte{byte(protocol.AuthenticatorGetInfo)})
	if err != nil {
		return protocol.AuthenticatorGetInfoResponse{}, err
	}

	var resp protocol.AuthenticatorGetInfoResponse
	if err := cl.decMode.Unmarshal(respRaw.Data, &resp); err != nil {
		return protocol.AuthenticatorGetInfoResponse{}, err
	}

	return resp, nil
}

func (cl *Client) GetPINRetries(
	ctx context.Context,
	pinUvAuthProtocol protocol.PinUvAuthProtocol,
) (uint, *bool, error) {
	if pinUvAuthProtocol != 0 {
		if err := pinvalidation.ValidateFIPS140UvAuthProtocol(pinUvAuthProtocol); err != nil {
			return 0, nil, err
		}
	}

	req := &protocol.AuthenticatorClientPINRequest{
		// Solo 2 requires pinUvAuthProtocol even for getPINRetries.
		PinUvAuthProtocol: pinUvAuthProtocol,
		SubCommand:        protocol.ClientPINSubCommandGetPINRetries,
	}

	b, err := cl.encMode.Marshal(req)
	if err != nil {
		return 0, nil, err
	}

	respRaw, err := cl.exchange(ctx, slices.Concat([]byte{byte(protocol.AuthenticatorClientPIN)}, b))
	if err != nil {
		return 0, nil, err
	}

	var resp *protocol.AuthenticatorClientPINResponse
	if err := cl.decMode.Unmarshal(respRaw.Data, &resp); err != nil {
		return 0, nil, err
	}

	if resp.PinRetries == nil {
		return 0, nil, errors.New("spec violation: pinRetries is nil")
	}

	return *resp.PinRetries, resp.PowerCycleState, nil
}

// GetUVRetries returns the remaining built-in user-verification attempts.
// pinUvAuthProtocol may be zero when the authenticator does not require it.
func (cl *Client) GetUVRetries(
	ctx context.Context,
	pinUvAuthProtocol protocol.PinUvAuthProtocol,
) (uint, error) {
	if pinUvAuthProtocol != 0 {
		if err := pinvalidation.ValidateFIPS140UvAuthProtocol(pinUvAuthProtocol); err != nil {
			return 0, err
		}
	}

	req := &protocol.AuthenticatorClientPINRequest{
		PinUvAuthProtocol: pinUvAuthProtocol,
		SubCommand:        protocol.ClientPINSubCommandGetUVRetries,
	}

	b, err := cl.encMode.Marshal(req)
	if err != nil {
		return 0, err
	}

	respRaw, err := cl.exchange(ctx, slices.Concat([]byte{byte(protocol.AuthenticatorClientPIN)}, b))
	if err != nil {
		return 0, err
	}

	var resp *protocol.AuthenticatorClientPINResponse
	if err := cl.decMode.Unmarshal(respRaw.Data, &resp); err != nil {
		return 0, err
	}

	if resp.UvRetries == nil {
		return 0, errors.New("spec violation: uvRetries is nil")
	}

	return *resp.UvRetries, err
}

func (cl *Client) GetKeyAgreement(
	ctx context.Context,
	pinUvAuthProtocol protocol.PinUvAuthProtocol,
) (cose.Key, error) {
	if err := pinvalidation.ValidateFIPS140UvAuthProtocol(pinUvAuthProtocol); err != nil {
		return nil, err
	}

	req := &protocol.AuthenticatorClientPINRequest{
		PinUvAuthProtocol: pinUvAuthProtocol,
		SubCommand:        protocol.ClientPINSubCommandGetKeyAgreement,
	}

	b, err := cl.encMode.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("cannot marshal keyAgreement CBOR request: %w", err)
	}

	respRaw, err := cl.exchange(ctx, slices.Concat([]byte{byte(protocol.AuthenticatorClientPIN)}, b))
	if err != nil {
		return nil, fmt.Errorf("keyAgreement CBOR request failed: %w", err)
	}

	var resp *protocol.AuthenticatorClientPINResponse
	if err := cl.decMode.Unmarshal(respRaw.Data, &resp); err != nil {
		return nil, fmt.Errorf("cannot unmarshal keyAgreement CBOR response: %w", err)
	}

	return resp.KeyAgreement, nil
}

func encryptNewPIN(
	pinProtocol *crypto.PinUvAuthProtocol,
	sharedSecret []byte,
	pin string,
) ([]byte, error) {
	pinBytes := make([]byte, 64)
	defer clear(pinBytes)

	copy(pinBytes, pin)

	return pinProtocol.Encrypt(sharedSecret, pinBytes)
}

func encryptPINHash(
	pinProtocol *crypto.PinUvAuthProtocol,
	sharedSecret []byte,
	pin string,
) ([]byte, error) {
	pinBytes := []byte(pin)
	defer clear(pinBytes)

	pinHash := sha256.Sum256(pinBytes)
	defer clear(pinHash[:])

	return pinProtocol.Encrypt(sharedSecret, pinHash[:16])
}

func (cl *Client) SetPIN(
	ctx context.Context,
	pinUvAuthProtocol protocol.PinUvAuthProtocol,
	keyAgreement cose.Key,
	pin string,
) error {
	pin, err := pinvalidation.NormalizeAndValidate(pin, protocol.DefaultMinPINCodePoints)
	if err != nil {
		return err
	}

	pinProtocol, err := crypto.NewPinUvAuthProtocol(pinUvAuthProtocol)
	if err != nil {
		return err
	}

	platformCoseKey, sharedSecret, err := pinProtocol.Encapsulate(keyAgreement)
	if err != nil {
		return err
	}
	defer clear(sharedSecret)

	newPinEnc, err := encryptNewPIN(pinProtocol, sharedSecret, pin)
	if err != nil {
		return err
	}

	pinUvAuthParam := crypto.Authenticate(
		pinUvAuthProtocol,
		sharedSecret,
		newPinEnc,
	)
	clear(sharedSecret)

	req := &protocol.AuthenticatorClientPINRequest{
		PinUvAuthProtocol: pinProtocol.Number,
		SubCommand:        protocol.ClientPINSubCommandSetPIN,
		KeyAgreement:      platformCoseKey,
		NewPinEnc:         newPinEnc,
		PinUvAuthParam:    pinUvAuthParam,
	}

	b, err := cl.encMode.Marshal(req)
	if err != nil {
		return err
	}

	if _, err := cl.exchange(ctx, slices.Concat([]byte{byte(protocol.AuthenticatorClientPIN)}, b)); err != nil {
		return err
	}

	return nil
}

func (cl *Client) ChangePIN(
	ctx context.Context,
	pinUvAuthProtocol protocol.PinUvAuthProtocol,
	keyAgreement cose.Key,
	currentPin string,
	newPin string,
) error {
	currentPin, err := pinvalidation.NormalizeAndValidate(currentPin, protocol.DefaultMinPINCodePoints)
	if err != nil {
		return err
	}

	newPin, err = pinvalidation.NormalizeAndValidate(newPin, protocol.DefaultMinPINCodePoints)
	if err != nil {
		return err
	}

	pinProtocol, err := crypto.NewPinUvAuthProtocol(pinUvAuthProtocol)
	if err != nil {
		return err
	}

	platformCoseKey, sharedSecret, err := pinProtocol.Encapsulate(keyAgreement)
	if err != nil {
		return err
	}
	defer clear(sharedSecret)

	pinHashEnc, err := encryptPINHash(pinProtocol, sharedSecret, currentPin)
	if err != nil {
		return err
	}

	newPinEnc, err := encryptNewPIN(pinProtocol, sharedSecret, newPin)
	if err != nil {
		return err
	}

	pinUvAuthParam := crypto.Authenticate(
		pinUvAuthProtocol,
		sharedSecret,
		slices.Concat(newPinEnc, pinHashEnc),
	)
	clear(sharedSecret)

	req := &protocol.AuthenticatorClientPINRequest{
		PinUvAuthProtocol: pinProtocol.Number,
		SubCommand:        protocol.ClientPINSubCommandChangePIN,
		KeyAgreement:      platformCoseKey,
		PinHashEnc:        pinHashEnc,
		NewPinEnc:         newPinEnc,
		PinUvAuthParam:    pinUvAuthParam,
	}

	b, err := cl.encMode.Marshal(req)
	if err != nil {
		return err
	}

	if _, err := cl.exchange(ctx, slices.Concat([]byte{byte(protocol.AuthenticatorClientPIN)}, b)); err != nil {
		return err
	}

	return nil
}

// GetPinToken obtains a legacy PIN/UV token without scoped permissions.
func (cl *Client) GetPinToken(
	ctx context.Context,
	pinUvAuthProtocol protocol.PinUvAuthProtocol,
	keyAgreement cose.Key,
	pin string,
) ([]byte, error) {
	pin, err := pinvalidation.NormalizeAndValidate(pin, protocol.DefaultMinPINCodePoints)
	if err != nil {
		return nil, err
	}

	pinProtocol, err := crypto.NewPinUvAuthProtocol(pinUvAuthProtocol)
	if err != nil {
		return nil, err
	}

	platformCoseKey, sharedSecret, err := pinProtocol.Encapsulate(keyAgreement)
	if err != nil {
		return nil, err
	}
	defer clear(sharedSecret)

	pinHashEnc, err := encryptPINHash(pinProtocol, sharedSecret, pin)
	if err != nil {
		return nil, err
	}

	req := &protocol.AuthenticatorClientPINRequest{
		PinUvAuthProtocol: pinProtocol.Number,
		SubCommand:        protocol.ClientPINSubCommandGetPinToken,
		KeyAgreement:      platformCoseKey,
		PinHashEnc:        pinHashEnc,
	}

	b, err := cl.encMode.Marshal(req)
	if err != nil {
		return nil, err
	}

	respRaw, err := cl.exchange(ctx, slices.Concat([]byte{byte(protocol.AuthenticatorClientPIN)}, b))
	if err != nil {
		return nil, err
	}

	var resp *protocol.AuthenticatorClientPINResponse
	if err := cl.decMode.Unmarshal(respRaw.Data, &resp); err != nil {
		return nil, err
	}

	pinUvAuthToken, err := pinProtocol.Decrypt(sharedSecret, resp.PinUvAuthToken)
	if err != nil {
		return nil, err
	}

	return pinUvAuthToken, nil
}

// GetPinUvAuthTokenUsingPinWithPermissions gets a PIN token with scoped permissions.
func (cl *Client) GetPinUvAuthTokenUsingPinWithPermissions(
	ctx context.Context,
	pinUvAuthProtocol protocol.PinUvAuthProtocol,
	keyAgreement cose.Key,
	pin string,
	permissions protocol.Permission,
	rpID string,
) ([]byte, error) {
	pin, err := pinvalidation.NormalizeAndValidate(pin, protocol.DefaultMinPINCodePoints)
	if err != nil {
		return nil, err
	}

	pinProtocol, err := crypto.NewPinUvAuthProtocol(pinUvAuthProtocol)
	if err != nil {
		return nil, err
	}

	platformCoseKey, sharedSecret, err := pinProtocol.Encapsulate(keyAgreement)
	if err != nil {
		return nil, err
	}
	defer clear(sharedSecret)

	pinHashEnc, err := encryptPINHash(pinProtocol, sharedSecret, pin)
	if err != nil {
		return nil, err
	}

	req := &protocol.AuthenticatorClientPINRequest{
		PinUvAuthProtocol: pinProtocol.Number,
		SubCommand:        protocol.ClientPINSubCommandGetPinUvAuthTokenUsingPinWithPermissions,
		KeyAgreement:      platformCoseKey,
		PinHashEnc:        pinHashEnc,
		Permissions:       permissions,
		RPID:              rpID,
	}

	b, err := cl.encMode.Marshal(req)
	if err != nil {
		return nil, err
	}

	respRaw, err := cl.exchange(ctx, slices.Concat([]byte{byte(protocol.AuthenticatorClientPIN)}, b))
	if err != nil {
		return nil, err
	}

	var resp *protocol.AuthenticatorClientPINResponse
	if err := cl.decMode.Unmarshal(respRaw.Data, &resp); err != nil {
		return nil, err
	}

	pinUvAuthToken, err := pinProtocol.Decrypt(sharedSecret, resp.PinUvAuthToken)
	if err != nil {
		return nil, err
	}

	return pinUvAuthToken, nil
}

// GetPinUvAuthTokenUsingUv gets a legacy FIDO_2_1_PRE UV token using protocol 1.
func (cl *Client) GetPinUvAuthTokenUsingUv(
	ctx context.Context,
	keyAgreement cose.Key,
) ([]byte, error) {
	return cl.getPinUvAuthTokenUsingUv(
		ctx,
		protocol.PinUvAuthProtocolOne,
		keyAgreement,
		protocol.PermissionNone,
		"",
	)
}

// GetPinUvAuthTokenUsingUvWithPermissions gets a UV token with scoped permissions.
func (cl *Client) GetPinUvAuthTokenUsingUvWithPermissions(
	ctx context.Context,
	pinUvAuthProtocol protocol.PinUvAuthProtocol,
	keyAgreement cose.Key,
	permissions protocol.Permission,
	rpID string,
) ([]byte, error) {
	return cl.getPinUvAuthTokenUsingUv(ctx, pinUvAuthProtocol, keyAgreement, permissions, rpID)
}

func (cl *Client) getPinUvAuthTokenUsingUv(
	ctx context.Context,
	pinUvAuthProtocol protocol.PinUvAuthProtocol,
	keyAgreement cose.Key,
	permissions protocol.Permission,
	rpID string,
) ([]byte, error) {
	pinProtocol, err := crypto.NewPinUvAuthProtocol(pinUvAuthProtocol)
	if err != nil {
		return nil, err
	}

	platformCoseKey, sharedSecret, err := pinProtocol.Encapsulate(keyAgreement)
	if err != nil {
		return nil, err
	}
	defer clear(sharedSecret)

	req := &protocol.AuthenticatorClientPINRequest{
		PinUvAuthProtocol: pinProtocol.Number,
		SubCommand:        protocol.ClientPINSubCommandGetPinUvAuthTokenUsingUvWithPermissions,
		KeyAgreement:      platformCoseKey,
		Permissions:       permissions,
		RPID:              rpID,
	}

	b, err := cl.encMode.Marshal(req)
	if err != nil {
		return nil, err
	}

	respRaw, err := cl.exchange(ctx, slices.Concat([]byte{byte(protocol.AuthenticatorClientPIN)}, b))
	if err != nil {
		return nil, err
	}

	var resp *protocol.AuthenticatorClientPINResponse
	if err := cl.decMode.Unmarshal(respRaw.Data, &resp); err != nil {
		return nil, err
	}

	pinUvAuthToken, err := pinProtocol.Decrypt(sharedSecret, resp.PinUvAuthToken)
	if err != nil {
		return nil, err
	}

	return pinUvAuthToken, nil
}

// Reset sends authenticatorReset.
func (cl *Client) Reset(ctx context.Context) error {
	_, err := cl.exchange(ctx, []byte{byte(protocol.AuthenticatorReset)})
	return err
}

func (cl *Client) GetBioModality(
	ctx context.Context,
	preview bool,
) (protocol.AuthenticatorBioEnrollmentResponse, error) {
	req := &protocol.AuthenticatorBioEnrollmentRequest{GetModality: true}

	b, err := cl.encMode.Marshal(req)
	if err != nil {
		return protocol.AuthenticatorBioEnrollmentResponse{}, err
	}

	command := protocol.AuthenticatorBioEnrollment
	if preview {
		command = protocol.PrototypeAuthenticatorBioEnrollment
	}

	respRaw, err := cl.exchange(ctx, slices.Concat([]byte{byte(command)}, b))
	if err != nil {
		return protocol.AuthenticatorBioEnrollmentResponse{}, err
	}

	var resp protocol.AuthenticatorBioEnrollmentResponse
	if err := cl.decMode.Unmarshal(respRaw.Data, &resp); err != nil {
		return protocol.AuthenticatorBioEnrollmentResponse{}, err
	}

	return resp, nil
}

func (cl *Client) GetFingerprintSensorInfo(
	ctx context.Context,
	preview bool,
) (protocol.AuthenticatorBioEnrollmentResponse, error) {
	req := &protocol.AuthenticatorBioEnrollmentRequest{
		Modality:   protocol.BioModalityFingerprint,
		SubCommand: protocol.BioEnrollmentSubCommandGetFingerprintSensorInfo,
	}

	b, err := cl.encMode.Marshal(req)
	if err != nil {
		return protocol.AuthenticatorBioEnrollmentResponse{}, err
	}

	command := protocol.AuthenticatorBioEnrollment
	if preview {
		command = protocol.PrototypeAuthenticatorBioEnrollment
	}

	respRaw, err := cl.exchange(ctx, slices.Concat([]byte{byte(command)}, b))
	if err != nil {
		return protocol.AuthenticatorBioEnrollmentResponse{}, err
	}

	var resp protocol.AuthenticatorBioEnrollmentResponse
	if err := cl.decMode.Unmarshal(respRaw.Data, &resp); err != nil {
		return protocol.AuthenticatorBioEnrollmentResponse{}, err
	}

	return resp, nil
}

func (cl *Client) EnrollBegin(
	ctx context.Context,
	preview bool,
	pinUvAuthProtocol protocol.PinUvAuthProtocol,
	pinUvAuthToken []byte,
	timeoutMilliseconds uint,
) (protocol.AuthenticatorBioEnrollmentResponse, error) {
	if err := pinvalidation.ValidateUvAuthToken(pinUvAuthProtocol, pinUvAuthToken); err != nil {
		return protocol.AuthenticatorBioEnrollmentResponse{}, err
	}

	bSubCommandParams, err := cl.encMode.Marshal(protocol.BioEnrollmentSubCommandParams{
		TimeoutMilliseconds: timeoutMilliseconds,
	})
	if err != nil {
		return protocol.AuthenticatorBioEnrollmentResponse{}, err
	}

	if timeoutMilliseconds == 0 {
		bSubCommandParams = nil
	}

	pinUvAuthParam := crypto.Authenticate(
		pinUvAuthProtocol,
		pinUvAuthToken,
		slices.Concat(
			[]byte{byte(protocol.BioModalityFingerprint), byte(protocol.BioEnrollmentSubCommandEnrollBegin)},
			bSubCommandParams,
		),
	)

	req := &protocol.AuthenticatorBioEnrollmentRequest{
		Modality:   protocol.BioModalityFingerprint,
		SubCommand: protocol.BioEnrollmentSubCommandEnrollBegin,
		SubCommandParams: protocol.BioEnrollmentSubCommandParams{
			TimeoutMilliseconds: timeoutMilliseconds,
		},
		PinUvAuthProtocol: pinUvAuthProtocol,
		PinUvAuthParam:    pinUvAuthParam,
	}

	b, err := cl.encMode.Marshal(req)
	if err != nil {
		return protocol.AuthenticatorBioEnrollmentResponse{}, err
	}

	command := protocol.AuthenticatorBioEnrollment
	if preview {
		command = protocol.PrototypeAuthenticatorBioEnrollment
	}

	respRaw, err := cl.exchange(ctx, slices.Concat([]byte{byte(command)}, b))
	if err != nil {
		return protocol.AuthenticatorBioEnrollmentResponse{}, err
	}

	var resp protocol.AuthenticatorBioEnrollmentResponse
	if err := cl.decMode.Unmarshal(respRaw.Data, &resp); err != nil {
		return protocol.AuthenticatorBioEnrollmentResponse{}, err
	}

	return resp, nil
}

func (cl *Client) EnrollCaptureNextSample(
	ctx context.Context,
	preview bool,
	pinUvAuthProtocol protocol.PinUvAuthProtocol,
	pinUvAuthToken []byte,
	templateID []byte,
	timeoutMilliseconds uint,
) (protocol.AuthenticatorBioEnrollmentResponse, error) {
	if err := pinvalidation.ValidateUvAuthToken(pinUvAuthProtocol, pinUvAuthToken); err != nil {
		return protocol.AuthenticatorBioEnrollmentResponse{}, err
	}

	bSubCommandParams, err := cl.encMode.Marshal(protocol.BioEnrollmentSubCommandParams{
		TemplateID:          templateID,
		TimeoutMilliseconds: timeoutMilliseconds,
	})
	if err != nil {
		return protocol.AuthenticatorBioEnrollmentResponse{}, err
	}

	pinUvAuthParam := crypto.Authenticate(
		pinUvAuthProtocol,
		pinUvAuthToken,
		slices.Concat(
			[]byte{byte(protocol.BioModalityFingerprint), byte(protocol.BioEnrollmentSubCommandEnrollCaptureNextSample)},
			bSubCommandParams,
		),
	)

	req := &protocol.AuthenticatorBioEnrollmentRequest{
		Modality:   protocol.BioModalityFingerprint,
		SubCommand: protocol.BioEnrollmentSubCommandEnrollCaptureNextSample,
		SubCommandParams: protocol.BioEnrollmentSubCommandParams{
			TemplateID:          templateID,
			TimeoutMilliseconds: timeoutMilliseconds,
		},
		PinUvAuthProtocol: pinUvAuthProtocol,
		PinUvAuthParam:    pinUvAuthParam,
	}

	b, err := cl.encMode.Marshal(req)
	if err != nil {
		return protocol.AuthenticatorBioEnrollmentResponse{}, err
	}

	command := protocol.AuthenticatorBioEnrollment
	if preview {
		command = protocol.PrototypeAuthenticatorBioEnrollment
	}

	respRaw, err := cl.exchange(ctx, slices.Concat([]byte{byte(command)}, b))
	if err != nil {
		return protocol.AuthenticatorBioEnrollmentResponse{}, err
	}

	var resp protocol.AuthenticatorBioEnrollmentResponse
	if err := cl.decMode.Unmarshal(respRaw.Data, &resp); err != nil {
		return protocol.AuthenticatorBioEnrollmentResponse{}, err
	}

	return resp, nil
}

func (cl *Client) CancelCurrentEnrollment(
	ctx context.Context,
	preview bool,
) error {
	req := &protocol.AuthenticatorBioEnrollmentRequest{
		Modality:   protocol.BioModalityFingerprint,
		SubCommand: protocol.BioEnrollmentSubCommandCancelCurrentEnrollment,
	}

	b, err := cl.encMode.Marshal(req)
	if err != nil {
		return err
	}

	command := protocol.AuthenticatorBioEnrollment
	if preview {
		command = protocol.PrototypeAuthenticatorBioEnrollment
	}

	if _, err := cl.exchange(ctx, slices.Concat([]byte{byte(command)}, b)); err != nil {
		return err
	}

	return nil
}

func (cl *Client) EnumerateEnrollments(
	ctx context.Context,
	preview bool,
	pinUvAuthProtocol protocol.PinUvAuthProtocol,
	pinUvAuthToken []byte,
) (protocol.AuthenticatorBioEnrollmentResponse, error) {
	if err := pinvalidation.ValidateUvAuthToken(pinUvAuthProtocol, pinUvAuthToken); err != nil {
		return protocol.AuthenticatorBioEnrollmentResponse{}, err
	}

	pinUvAuthParam := crypto.Authenticate(
		pinUvAuthProtocol,
		pinUvAuthToken,
		[]byte{byte(protocol.BioModalityFingerprint), byte(protocol.BioEnrollmentSubCommandEnumerateEnrollments)},
	)

	req := &protocol.AuthenticatorBioEnrollmentRequest{
		Modality:          protocol.BioModalityFingerprint,
		SubCommand:        protocol.BioEnrollmentSubCommandEnumerateEnrollments,
		PinUvAuthProtocol: pinUvAuthProtocol,
		PinUvAuthParam:    pinUvAuthParam,
	}

	b, err := cl.encMode.Marshal(req)
	if err != nil {
		return protocol.AuthenticatorBioEnrollmentResponse{}, err
	}

	command := protocol.AuthenticatorBioEnrollment
	if preview {
		command = protocol.PrototypeAuthenticatorBioEnrollment
	}

	respRaw, err := cl.exchange(ctx, slices.Concat([]byte{byte(command)}, b))
	if err != nil {
		return protocol.AuthenticatorBioEnrollmentResponse{}, err
	}

	var resp protocol.AuthenticatorBioEnrollmentResponse
	if err := cl.decMode.Unmarshal(respRaw.Data, &resp); err != nil {
		return protocol.AuthenticatorBioEnrollmentResponse{}, err
	}

	return resp, nil
}

func (cl *Client) SetFriendlyName(
	ctx context.Context,
	preview bool,
	pinUvAuthProtocol protocol.PinUvAuthProtocol,
	pinUvAuthToken []byte,
	templateID []byte,
	friendlyName string,
) error {
	if err := pinvalidation.ValidateUvAuthToken(pinUvAuthProtocol, pinUvAuthToken); err != nil {
		return err
	}

	bSubCommandParams, err := cl.encMode.Marshal(protocol.BioEnrollmentSubCommandParams{
		TemplateID:           templateID,
		TemplateFriendlyName: &friendlyName,
	})
	if err != nil {
		return err
	}

	pinUvAuthParam := crypto.Authenticate(
		pinUvAuthProtocol,
		pinUvAuthToken,
		slices.Concat(
			[]byte{byte(protocol.BioModalityFingerprint), byte(protocol.BioEnrollmentSubCommandSetFriendlyName)},
			bSubCommandParams,
		),
	)

	req := &protocol.AuthenticatorBioEnrollmentRequest{
		Modality:   protocol.BioModalityFingerprint,
		SubCommand: protocol.BioEnrollmentSubCommandSetFriendlyName,
		SubCommandParams: protocol.BioEnrollmentSubCommandParams{
			TemplateID:           templateID,
			TemplateFriendlyName: &friendlyName,
		},
		PinUvAuthProtocol: pinUvAuthProtocol,
		PinUvAuthParam:    pinUvAuthParam,
	}

	b, err := cl.encMode.Marshal(req)
	if err != nil {
		return err
	}

	command := protocol.AuthenticatorBioEnrollment
	if preview {
		command = protocol.PrototypeAuthenticatorBioEnrollment
	}

	if _, err := cl.exchange(ctx, slices.Concat([]byte{byte(command)}, b)); err != nil {
		return err
	}

	return nil
}

func (cl *Client) RemoveEnrollment(
	ctx context.Context,
	preview bool,
	pinUvAuthProtocol protocol.PinUvAuthProtocol,
	pinUvAuthToken []byte,
	templateID []byte,
) error {
	if err := pinvalidation.ValidateUvAuthToken(pinUvAuthProtocol, pinUvAuthToken); err != nil {
		return err
	}

	bSubCommandParams, err := cl.encMode.Marshal(protocol.BioEnrollmentSubCommandParams{
		TemplateID: templateID,
	})
	if err != nil {
		return err
	}

	pinUvAuthParam := crypto.Authenticate(
		pinUvAuthProtocol,
		pinUvAuthToken,
		slices.Concat(
			[]byte{byte(protocol.BioModalityFingerprint), byte(protocol.BioEnrollmentSubCommandRemoveEnrollment)},
			bSubCommandParams,
		),
	)

	req := &protocol.AuthenticatorBioEnrollmentRequest{
		Modality:   protocol.BioModalityFingerprint,
		SubCommand: protocol.BioEnrollmentSubCommandRemoveEnrollment,
		SubCommandParams: protocol.BioEnrollmentSubCommandParams{
			TemplateID: templateID,
		},
		PinUvAuthProtocol: pinUvAuthProtocol,
		PinUvAuthParam:    pinUvAuthParam,
	}

	b, err := cl.encMode.Marshal(req)
	if err != nil {
		return err
	}

	command := protocol.AuthenticatorBioEnrollment
	if preview {
		command = protocol.PrototypeAuthenticatorBioEnrollment
	}

	if _, err := cl.exchange(ctx, slices.Concat([]byte{byte(command)}, b)); err != nil {
		return err
	}

	return nil
}

func (cl *Client) GetCredsMetadata(
	ctx context.Context,
	preview bool,
	pinUvAuthProtocol protocol.PinUvAuthProtocol,
	pinUvAuthToken []byte,
) (protocol.AuthenticatorCredentialManagementResponse, error) {
	if err := pinvalidation.ValidateUvAuthToken(pinUvAuthProtocol, pinUvAuthToken); err != nil {
		return protocol.AuthenticatorCredentialManagementResponse{}, err
	}

	pinUvAuthParam := crypto.Authenticate(
		pinUvAuthProtocol,
		pinUvAuthToken,
		[]byte{byte(protocol.CredentialManagementSubCommandGetCredsMetadata)},
	)

	req := &protocol.AuthenticatorCredentialManagementRequest{
		SubCommand:        protocol.CredentialManagementSubCommandGetCredsMetadata,
		PinUvAuthProtocol: pinUvAuthProtocol,
		PinUvAuthParam:    pinUvAuthParam,
	}

	b, err := cl.encMode.Marshal(req)
	if err != nil {
		return protocol.AuthenticatorCredentialManagementResponse{}, err
	}

	command := protocol.AuthenticatorCredentialManagement
	if preview {
		command = protocol.PrototypeAuthenticatorCredentialManagement
	}

	respRaw, err := cl.exchange(ctx, slices.Concat([]byte{byte(command)}, b))
	if err != nil {
		return protocol.AuthenticatorCredentialManagementResponse{}, err
	}

	var resp protocol.AuthenticatorCredentialManagementResponse
	if err := cl.decMode.Unmarshal(respRaw.Data, &resp); err != nil {
		return protocol.AuthenticatorCredentialManagementResponse{}, err
	}

	return resp, nil
}

// EnumerateRPs yields the authenticator's relying parties.
// Consume it before any other Client call, including EnumerateCredentials.
func (cl *Client) EnumerateRPs(
	ctx context.Context,
	preview bool,
	pinUvAuthProtocol protocol.PinUvAuthProtocol,
	pinUvAuthToken []byte,
) iter.Seq2[protocol.AuthenticatorCredentialManagementResponse, error] {
	return func(yield func(protocol.AuthenticatorCredentialManagementResponse, error) bool) {
		if err := pinvalidation.ValidateUvAuthToken(pinUvAuthProtocol, pinUvAuthToken); err != nil {
			yield(protocol.AuthenticatorCredentialManagementResponse{}, err)
			return
		}

		pinUvAuthParamBegin := crypto.Authenticate(
			pinUvAuthProtocol,
			pinUvAuthToken,
			[]byte{byte(protocol.CredentialManagementSubCommandEnumerateRPsBegin)},
		)

		reqBegin := &protocol.AuthenticatorCredentialManagementRequest{
			SubCommand:        protocol.CredentialManagementSubCommandEnumerateRPsBegin,
			PinUvAuthProtocol: pinUvAuthProtocol,
			PinUvAuthParam:    pinUvAuthParamBegin,
		}

		bBegin, err := cl.encMode.Marshal(reqBegin)
		if err != nil {
			yield(protocol.AuthenticatorCredentialManagementResponse{}, err)
			return
		}

		command := protocol.AuthenticatorCredentialManagement
		if preview {
			command = protocol.PrototypeAuthenticatorCredentialManagement
		}

		respRawBegin, err := cl.exchange(
			ctx,
			slices.Concat(
				[]byte{byte(command)},
				bBegin,
			),
		)
		if err != nil {
			yield(protocol.AuthenticatorCredentialManagementResponse{}, err)
			return
		}

		var respBegin protocol.AuthenticatorCredentialManagementResponse
		if err := cl.decMode.Unmarshal(respRawBegin.Data, &respBegin); err != nil {
			yield(protocol.AuthenticatorCredentialManagementResponse{}, err)
			return
		}

		if respBegin.TotalRPs == 0 {
			yield(protocol.AuthenticatorCredentialManagementResponse{}, errors.New("spec violation: totalRPs is missing or zero in enumerateRPsBegin response"))
			return
		}

		if !yield(respBegin, nil) {
			return
		}

		for i := uint(1); i < respBegin.TotalRPs; i++ {
			reqNext := &protocol.AuthenticatorCredentialManagementRequest{
				SubCommand: protocol.CredentialManagementSubCommandEnumerateRPsGetNextRP,
			}

			bNext, err := cl.encMode.Marshal(reqNext)
			if err != nil {
				yield(protocol.AuthenticatorCredentialManagementResponse{}, err)
				return
			}

			respRawNext, err := cl.exchange(ctx, slices.Concat([]byte{byte(command)}, bNext))
			if err != nil {
				yield(protocol.AuthenticatorCredentialManagementResponse{}, err)
				return
			}

			var respNext protocol.AuthenticatorCredentialManagementResponse
			if err := cl.decMode.Unmarshal(respRawNext.Data, &respNext); err != nil {
				yield(protocol.AuthenticatorCredentialManagementResponse{}, err)
				return
			}

			if !yield(respNext, nil) {
				return
			}
		}
	}
}

// EnumerateCredentials yields credentials for one relying party.
// Consume it before another Client call; do not nest it inside EnumerateRPs.
func (cl *Client) EnumerateCredentials(
	ctx context.Context,
	preview bool,
	pinUvAuthProtocol protocol.PinUvAuthProtocol,
	pinUvAuthToken []byte,
	rpIDHash []byte,
) iter.Seq2[protocol.AuthenticatorCredentialManagementResponse, error] {
	return func(yield func(protocol.AuthenticatorCredentialManagementResponse, error) bool) {
		if err := pinvalidation.ValidateUvAuthToken(pinUvAuthProtocol, pinUvAuthToken); err != nil {
			yield(protocol.AuthenticatorCredentialManagementResponse{}, err)
			return
		}

		bSubCommandParams, err := cl.encMode.Marshal(protocol.CredentialManagementSubCommandParams{RPIDHash: rpIDHash})
		if err != nil {
			yield(protocol.AuthenticatorCredentialManagementResponse{}, err)
			return
		}

		pinUvAuthParamBegin := crypto.Authenticate(
			pinUvAuthProtocol,
			pinUvAuthToken,
			slices.Concat(
				[]byte{byte(protocol.CredentialManagementSubCommandEnumerateCredentialsBegin)},
				bSubCommandParams,
			),
		)

		reqBegin := &protocol.AuthenticatorCredentialManagementRequest{
			SubCommand:        protocol.CredentialManagementSubCommandEnumerateCredentialsBegin,
			SubCommandParams:  protocol.CredentialManagementSubCommandParams{RPIDHash: rpIDHash},
			PinUvAuthProtocol: pinUvAuthProtocol,
			PinUvAuthParam:    pinUvAuthParamBegin,
		}

		bBegin, err := cl.encMode.Marshal(reqBegin)
		if err != nil {
			yield(protocol.AuthenticatorCredentialManagementResponse{}, err)
			return
		}

		command := protocol.AuthenticatorCredentialManagement
		if preview {
			command = protocol.PrototypeAuthenticatorCredentialManagement
		}

		respRawBegin, err := cl.exchange(
			ctx,
			slices.Concat(
				[]byte{byte(command)},
				bBegin,
			),
		)
		if err != nil {
			yield(protocol.AuthenticatorCredentialManagementResponse{}, err)
			return
		}

		var respBegin protocol.AuthenticatorCredentialManagementResponse
		if err := cl.decMode.Unmarshal(respRawBegin.Data, &respBegin); err != nil {
			yield(protocol.AuthenticatorCredentialManagementResponse{}, err)
			return
		}

		if respBegin.TotalCredentials == 0 {
			yield(protocol.AuthenticatorCredentialManagementResponse{}, errors.New("spec violation: totalCredentials is missing or zero in enumerateCredentialsBegin response"))
			return
		}

		if !yield(respBegin, nil) {
			return
		}

		for i := uint(1); i < respBegin.TotalCredentials; i++ {
			reqNext := &protocol.AuthenticatorCredentialManagementRequest{
				SubCommand: protocol.CredentialManagementSubCommandEnumerateCredentialsGetNextCredential,
			}

			bNext, err := cl.encMode.Marshal(reqNext)
			if err != nil {
				yield(protocol.AuthenticatorCredentialManagementResponse{}, err)
				return
			}

			respRawNext, err := cl.exchange(ctx, slices.Concat([]byte{byte(command)}, bNext))
			if err != nil {
				yield(protocol.AuthenticatorCredentialManagementResponse{}, err)
				return
			}

			var respNext protocol.AuthenticatorCredentialManagementResponse
			if err := cl.decMode.Unmarshal(respRawNext.Data, &respNext); err != nil {
				yield(protocol.AuthenticatorCredentialManagementResponse{}, err)
				return
			}

			if !yield(respNext, nil) {
				return
			}
		}
	}
}

func (cl *Client) DeleteCredential(
	ctx context.Context,
	preview bool,
	pinUvAuthProtocol protocol.PinUvAuthProtocol,
	pinUvAuthToken []byte,
	credentialID credential.PublicKeyCredentialDescriptor,
) error {
	if err := pinvalidation.ValidateUvAuthToken(pinUvAuthProtocol, pinUvAuthToken); err != nil {
		return err
	}

	bSubCommandParams, err := cl.encMode.Marshal(protocol.CredentialManagementSubCommandParams{
		CredentialID: credentialID,
	})
	if err != nil {
		return err
	}

	pinUvAuthParam := crypto.Authenticate(
		pinUvAuthProtocol,
		pinUvAuthToken,
		slices.Concat(
			[]byte{byte(protocol.CredentialManagementSubCommandDeleteCredential)},
			bSubCommandParams,
		),
	)

	req := &protocol.AuthenticatorCredentialManagementRequest{
		SubCommand:        protocol.CredentialManagementSubCommandDeleteCredential,
		SubCommandParams:  protocol.CredentialManagementSubCommandParams{CredentialID: credentialID},
		PinUvAuthProtocol: pinUvAuthProtocol,
		PinUvAuthParam:    pinUvAuthParam,
	}

	b, err := cl.encMode.Marshal(req)
	if err != nil {
		return err
	}

	command := protocol.AuthenticatorCredentialManagement
	if preview {
		command = protocol.PrototypeAuthenticatorCredentialManagement
	}

	if _, err := cl.exchange(ctx, slices.Concat([]byte{byte(command)}, b)); err != nil {
		return err
	}

	return nil
}

func (cl *Client) UpdateUserInformation(
	ctx context.Context,
	preview bool,
	pinUvAuthProtocol protocol.PinUvAuthProtocol,
	pinUvAuthToken []byte,
	credentialID credential.PublicKeyCredentialDescriptor,
	user credential.PublicKeyCredentialUserEntity,
) error {
	if err := pinvalidation.ValidateUvAuthToken(pinUvAuthProtocol, pinUvAuthToken); err != nil {
		return err
	}

	bSubCommandParams, err := cl.encMode.Marshal(protocol.CredentialManagementSubCommandParams{
		CredentialID: credentialID,
		User:         user,
	})
	if err != nil {
		return err
	}

	pinUvAuthParam := crypto.Authenticate(
		pinUvAuthProtocol,
		pinUvAuthToken,
		slices.Concat(
			[]byte{byte(protocol.CredentialManagementSubCommandUpdateUserInformation)},
			bSubCommandParams,
		),
	)

	req := &protocol.AuthenticatorCredentialManagementRequest{
		SubCommand: protocol.CredentialManagementSubCommandUpdateUserInformation,
		SubCommandParams: protocol.CredentialManagementSubCommandParams{
			CredentialID: credentialID,
			User:         user,
		},
		PinUvAuthProtocol: pinUvAuthProtocol,
		PinUvAuthParam:    pinUvAuthParam,
	}

	b, err := cl.encMode.Marshal(req)
	if err != nil {
		return err
	}

	command := protocol.AuthenticatorCredentialManagement
	if preview {
		command = protocol.PrototypeAuthenticatorCredentialManagement
	}

	if _, err := cl.exchange(ctx, slices.Concat([]byte{byte(command)}, b)); err != nil {
		return err
	}

	return nil
}

// Selection blocks until the user confirms presence or ctx is canceled.
func (cl *Client) Selection(ctx context.Context) error {
	_, err := cl.exchange(ctx, []byte{byte(protocol.AuthenticatorSelection)})
	return normalizeSelectionError(err)
}

func normalizeSelectionError(err error) error {
	if ctapError, ok := errors.AsType[*ctaptransport.CTAPError](err); ok && ctapError.StatusCode == ctaptransport.CTAP2_ERR_KEEPALIVE_CANCEL {
		return nil
	}

	return err
}

func (cl *Client) LargeBlobs(
	ctx context.Context,
	pinUvAuthProtocol protocol.PinUvAuthProtocol,
	pinUvAuthToken []byte,
	get uint,
	set []byte,
	offset uint,
	length uint,
) (protocol.AuthenticatorLargeBlobsResponse, error) {
	var getParam *uint
	if set == nil || get != 0 {
		getParam = &get
	}

	req := &protocol.AuthenticatorLargeBlobsRequest{
		Get:    getParam,
		Set:    set,
		Offset: offset,
		Length: length,
	}

	if pinUvAuthToken != nil {
		if err := pinvalidation.ValidateUvAuthToken(pinUvAuthProtocol, pinUvAuthToken); err != nil {
			return protocol.AuthenticatorLargeBlobsResponse{}, err
		}

		padding := make([]byte, 32)
		for i := range padding {
			padding[i] = 0xff
		}

		offsetBin := make([]byte, 4)
		binary.LittleEndian.PutUint32(offsetBin, uint32(offset))

		hasher := sha256.New()
		hasher.Reset()
		hasher.Write(set)
		hash := hasher.Sum(nil)

		pinUvAuthParam := crypto.Authenticate(
			pinUvAuthProtocol,
			pinUvAuthToken,
			slices.Concat(
				padding,
				[]byte{0x0c, 0x00},
				offsetBin,
				hash,
			),
		)

		req.PinUvAuthParam = pinUvAuthParam
		req.PinUvAuthProtocol = pinUvAuthProtocol
	}

	b, err := cl.encMode.Marshal(req)
	if err != nil {
		return protocol.AuthenticatorLargeBlobsResponse{}, err
	}

	respRaw, err := cl.exchange(ctx, slices.Concat([]byte{byte(protocol.AuthenticatorLargeBlobs)}, b))
	if err != nil {
		return protocol.AuthenticatorLargeBlobsResponse{}, err
	}

	var resp protocol.AuthenticatorLargeBlobsResponse
	if getParam != nil {
		if err := cl.decMode.Unmarshal(respRaw.Data, &resp); err != nil {
			return protocol.AuthenticatorLargeBlobsResponse{}, err
		}
	}

	return resp, nil
}

func (cl *Client) EnableEnterpriseAttestation(
	ctx context.Context,
	pinUvAuthProtocol protocol.PinUvAuthProtocol,
	pinUvAuthToken []byte,
) error {
	req := &protocol.AuthenticatorConfigRequest{
		SubCommand: protocol.ConfigSubCommandEnableEnterpriseAttestation,
	}

	if pinUvAuthToken != nil {
		if err := pinvalidation.ValidateUvAuthToken(pinUvAuthProtocol, pinUvAuthToken); err != nil {
			return err
		}

		padding := make([]byte, 32)
		for i := range padding {
			padding[i] = 0xff
		}

		req.PinUvAuthProtocol = pinUvAuthProtocol
		req.PinUvAuthParam = crypto.Authenticate(
			pinUvAuthProtocol,
			pinUvAuthToken,
			slices.Concat(
				padding,
				[]byte{0x0d, byte(protocol.ConfigSubCommandEnableEnterpriseAttestation)},
			),
		)
	}

	b, err := cl.encMode.Marshal(req)
	if err != nil {
		return err
	}

	if _, err := cl.exchange(ctx, slices.Concat([]byte{byte(protocol.AuthenticatorConfig)}, b)); err != nil {
		return err
	}

	return nil
}

func (cl *Client) ToggleAlwaysUV(
	ctx context.Context,
	pinUvAuthProtocol protocol.PinUvAuthProtocol,
	pinUvAuthToken []byte,
) error {
	req := &protocol.AuthenticatorConfigRequest{
		SubCommand: protocol.ConfigSubCommandToggleAlwaysUv,
	}

	if pinUvAuthToken != nil {
		if err := pinvalidation.ValidateUvAuthToken(pinUvAuthProtocol, pinUvAuthToken); err != nil {
			return err
		}

		padding := make([]byte, 32)
		for i := range padding {
			padding[i] = 0xff
		}

		req.PinUvAuthProtocol = pinUvAuthProtocol
		req.PinUvAuthParam = crypto.Authenticate(
			pinUvAuthProtocol,
			pinUvAuthToken,
			slices.Concat(
				padding,
				[]byte{0x0d, byte(protocol.ConfigSubCommandToggleAlwaysUv)},
			),
		)
	}

	b, err := cl.encMode.Marshal(req)
	if err != nil {
		return err
	}

	if _, err := cl.exchange(ctx, slices.Concat([]byte{byte(protocol.AuthenticatorConfig)}, b)); err != nil {
		return err
	}

	return nil
}

// SetMinPINLength updates the supplied CTAP 2.3 PIN policy parameters.
func (cl *Client) SetMinPINLength(
	ctx context.Context,
	pinUvAuthProtocol protocol.PinUvAuthProtocol,
	pinUvAuthToken []byte,
	params protocol.SetMinPINLengthConfigSubCommandParams,
) error {
	subCommandParams := &params

	bSubCommandParams, err := cl.encMode.Marshal(subCommandParams)
	if err != nil {
		return err
	}

	req := &protocol.AuthenticatorConfigRequest{
		SubCommand:       protocol.ConfigSubCommandSetMinPINLength,
		SubCommandParams: subCommandParams,
	}

	if pinUvAuthToken != nil {
		if err := pinvalidation.ValidateUvAuthToken(pinUvAuthProtocol, pinUvAuthToken); err != nil {
			return err
		}

		padding := make([]byte, 32)
		for i := range padding {
			padding[i] = 0xff
		}

		req.PinUvAuthProtocol = pinUvAuthProtocol
		req.PinUvAuthParam = crypto.Authenticate(
			pinUvAuthProtocol,
			pinUvAuthToken,
			slices.Concat(
				padding,
				[]byte{0x0d, byte(protocol.ConfigSubCommandSetMinPINLength)},
				bSubCommandParams,
			),
		)
	}

	b, err := cl.encMode.Marshal(req)
	if err != nil {
		return err
	}

	if _, err := cl.exchange(ctx, slices.Concat([]byte{byte(protocol.AuthenticatorConfig)}, b)); err != nil {
		return err
	}

	return nil
}

// EnableLongTouchForReset enables the long-touch requirement for authenticatorReset.
func (cl *Client) EnableLongTouchForReset(
	ctx context.Context,
	pinUvAuthProtocol protocol.PinUvAuthProtocol,
	pinUvAuthToken []byte,
) error {
	req := &protocol.AuthenticatorConfigRequest{
		SubCommand: protocol.ConfigSubCommandEnableLongTouchForReset,
	}

	if pinUvAuthToken != nil {
		if err := pinvalidation.ValidateUvAuthToken(pinUvAuthProtocol, pinUvAuthToken); err != nil {
			return err
		}

		padding := make([]byte, 32)
		for i := range padding {
			padding[i] = 0xff
		}

		req.PinUvAuthProtocol = pinUvAuthProtocol
		req.PinUvAuthParam = crypto.Authenticate(
			pinUvAuthProtocol,
			pinUvAuthToken,
			slices.Concat(
				padding,
				[]byte{0x0d, byte(protocol.ConfigSubCommandEnableLongTouchForReset)},
			),
		)
	}

	b, err := cl.encMode.Marshal(req)
	if err != nil {
		return err
	}

	if _, err := cl.exchange(ctx, slices.Concat([]byte{byte(protocol.AuthenticatorConfig)}, b)); err != nil {
		return err
	}

	return nil
}
