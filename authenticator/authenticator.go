package authenticator

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"iter"
	"slices"
	"sync"

	"github.com/fxamacker/cbor/v2"
	"github.com/telesma-app/ctap/attestation"
	"github.com/telesma-app/ctap/client"
	"github.com/telesma-app/ctap/cose"
	"github.com/telesma-app/ctap/credential"
	"github.com/telesma-app/ctap/crypto"
	"github.com/telesma-app/ctap/extension"
	"github.com/telesma-app/ctap/internal/fips140policy"
	pinvalidation "github.com/telesma-app/ctap/internal/pin"
	"github.com/telesma-app/ctap/options"
	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/ctap/transport/ctaphid"
	"github.com/telesma-app/ctap/webauthn"
)

// Device represents a physical or virtual hardware device supporting CTAP communication protocols.
type Device struct {
	transport  ctaptransport.Device
	info       protocol.AuthenticatorGetInfoResponse
	infoValid  bool
	ctapClient *client.Client
	mu         sync.Mutex   // global mutex to serialize requests to the device
	infoMu     sync.RWMutex // protects info and infoValid for cache-only access
}

func newHMACSecretInput(
	keyAgreement cose.Key,
	saltEnc []byte,
	saltAuth []byte,
	pinUvAuthProtocol protocol.PinUvAuthProtocol,
) protocol.HMACSecret {
	input := protocol.HMACSecret{
		KeyAgreement: keyAgreement,
		SaltEnc:      saltEnc,
		SaltAuth:     saltAuth,
	}
	// CTAP 2.0 defines only keys 1-3. CTAP 2.1+ requires key 4 only
	// when a protocol other than protocol one is used.
	if pinUvAuthProtocol != protocol.PinUvAuthProtocolOne {
		input.PinUvAuthProtocol = pinUvAuthProtocol
	}

	return input
}

type pinger interface {
	Ping(ctx context.Context, data []byte) ([]byte, error)
}

type winker interface {
	Wink(ctx context.Context) error
}

type locker interface {
	Lock(ctx context.Context, seconds uint8) error
}

func (d *Device) requirePinUvAuthProtocol() (protocol.PinUvAuthProtocol, error) {
	var policyErr error

	for _, candidate := range d.info.PinUvAuthProtocols {
		switch candidate {
		case protocol.PinUvAuthProtocolOne, protocol.PinUvAuthProtocolTwo:
			if err := pinvalidation.ValidateFIPS140UvAuthProtocol(candidate); err != nil {
				policyErr = err
				continue
			}

			return candidate, nil
		}
	}

	if policyErr != nil {
		return 0, policyErr
	}

	// FIDO_2_1_PRE RD 2019 makes pinUvAuthProtocols optional and defines
	// protocol 1 as the only valid protocol for the uvToken flow.
	if len(d.info.PinUvAuthProtocols) == 0 &&
		d.info.Versions.IsPreviewOnly() && d.info.Options[protocol.OptionUvToken] {
		if err := pinvalidation.ValidateFIPS140UvAuthProtocol(protocol.PinUvAuthProtocolOne); err != nil {
			return 0, err
		}

		return protocol.PinUvAuthProtocolOne, nil
	}

	return 0, &ErrorWithMessage{Err: ErrNotSupported, Message: "device didn't report a supported pinUvAuthProtocol"}
}

func (d *Device) pinUvAuthProtocolWithKeyAgreement(ctx context.Context) (protocol.PinUvAuthProtocol, cose.Key, error) {
	pinUvAuthProtocol, err := d.requirePinUvAuthProtocol()
	if err != nil {
		return 0, nil, err
	}

	keyAgreement, err := d.ctapClient.GetKeyAgreement(ctx, pinUvAuthProtocol)
	if err != nil {
		return 0, nil, err
	}

	return pinUvAuthProtocol, keyAgreement, nil
}

func (d *Device) refreshInfoLocked(ctx context.Context) (protocol.AuthenticatorGetInfoResponse, error) {
	info, err := d.ctapClient.GetInfo(ctx)
	if err != nil {
		return protocol.AuthenticatorGetInfoResponse{}, err
	}

	d.infoMu.Lock()
	d.info = info
	d.infoValid = true
	d.infoMu.Unlock()

	return info, nil
}

func (d *Device) ensureInfoLocked(ctx context.Context) error {
	d.infoMu.RLock()
	valid := d.infoValid
	d.infoMu.RUnlock()

	if valid {
		return nil
	}

	_, err := d.refreshInfoLocked(ctx)

	return err
}

func (d *Device) invalidateInfoLocked() {
	d.infoMu.Lock()
	defer d.infoMu.Unlock()

	d.infoValid = false
}

func (d *Device) maxFragmentLength() uint {
	return d.info.EffectiveMaxMsgSize() - 64
}

// New creates a Device over an initialized transport. The caller retains
// ownership of transport if New returns an error. The returned Device owns
// transport on success.
func New(ctx context.Context, transport ctaptransport.Device, opts ...options.Option) (*Device, error) {
	clientOpts := append(slices.Clone(opts), options.WithTransport(transport))

	ctapClient, err := client.NewClient(clientOpts...)
	if err != nil {
		return nil, err
	}

	d := &Device{
		transport:  transport,
		ctapClient: ctapClient,
	}

	info, err := d.ctapClient.GetInfo(ctx)
	if err != nil {
		return nil, err
	}

	d.info = info
	d.infoValid = true

	return d, nil
}

// Close closes the underlying transport.
func (d *Device) Close() error {
	return d.transport.Close()
}

// Ping sends a ping message to the device and verifies the response matches the sent data.
// Returns an error on failure.
func (d *Device) Ping(ctx context.Context, ping []byte) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	transport, ok := d.transport.(pinger)
	if !ok {
		return &ErrorWithMessage{Err: ErrNotSupported, Message: "ping requires CTAPHID"}
	}

	pong, err := transport.Ping(ctx, ping)
	if err != nil {
		return err
	}

	if !bytes.Equal(ping, pong) {
		return ErrPingPongMismatch
	}

	return nil
}

// Wink sends a blink command to the device to visually signal its presence to the user.
// It uses the CTAPHID_WINK command, which is optional and could be unsupported by some devices.
func (d *Device) Wink(ctx context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	transport, ok := d.transport.(winker)
	if !ok {
		return &ErrorWithMessage{Err: ErrNotSupported, Message: "wink requires CTAPHID"}
	}

	return transport.Wink(ctx)
}

// Lock places an exclusive lock for one channel to communicate with the device.
// As long as the lock is active, any other channel trying to send a message will fail.
// Send 0 seconds to unlock the channel.
func (d *Device) Lock(ctx context.Context, seconds uint) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	transport, ok := d.transport.(locker)
	if !ok {
		return &ErrorWithMessage{Err: ErrNotSupported, Message: "lock requires CTAPHID"}
	}

	if seconds > 10 {
		return &ErrorWithMessage{Err: SyntaxError, Message: "lock seconds must be between 0 and 10"}
	}

	return transport.Lock(ctx, uint8(seconds))
}

// MakeCredential initiates the process of creating a new credential on a device with specified parameters and options.
func (d *Device) MakeCredential(
	ctx context.Context,
	pinUvAuthToken []byte,
	clientData []byte,
	rp credential.PublicKeyCredentialRpEntity,
	user credential.PublicKeyCredentialUserEntity,
	pubKeyCredParams []credential.PublicKeyCredentialParameters,
	excludeList []credential.PublicKeyCredentialDescriptor,
	extInputs *webauthn.CreateAuthenticationExtensionsClientInputs,
	options map[protocol.Option]bool,
	enterpriseAttestation uint,
	attestationFormatsPreference []attestation.AttestationStatementFormatIdentifier,
) (protocol.AuthenticatorMakeCredentialResponse, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	pubKeyCredParams, err := fips140policy.FilterCredentialParameters(pubKeyCredParams)
	if err != nil {
		return protocol.AuthenticatorMakeCredentialResponse{}, err
	}

	if err := d.ensureInfoLocked(ctx); err != nil {
		return protocol.AuthenticatorMakeCredentialResponse{}, err
	}

	if extInputs == nil {
		extInputs = &webauthn.CreateAuthenticationExtensionsClientInputs{}
	}

	if extInputs.CreateHMACSecretMCInputs != nil && extInputs.PRFInputs != nil {
		return protocol.AuthenticatorMakeCredentialResponse{}, &ErrorWithMessage{Err: SyntaxError, Message: "you cannot use hmac-secret-mc and prf extensions at the same time"}
	}

	createPRFEvaluation, err := validateCreatePRF(d.info, pinUvAuthToken, extInputs, options)
	if err != nil {
		return protocol.AuthenticatorMakeCredentialResponse{}, err
	}

	if err := validateMakeCredentialAuthorization(d.info, pinUvAuthToken, options); err != nil {
		return protocol.AuthenticatorMakeCredentialResponse{}, err
	}

	var (
		pinUvAuthProtocol protocol.PinUvAuthProtocol
		pinProtocol       *crypto.PinUvAuthProtocol
		sharedSecret      []byte
	)

	if pinUvAuthToken != nil {
		var err error

		pinUvAuthProtocol, err = d.pinUvAuthProtocolForRequest(pinUvAuthToken, true)
		if err != nil {
			return protocol.AuthenticatorMakeCredentialResponse{}, err
		}
	}

	extensions := new(protocol.CreateExtensionInputs)

	// largeBlob
	var (
		backend               largeBlobBackend
		largeBlobSupport      extension.LargeBlobSupport
		largeBlobKeyRequested bool
	)
	if extInputs.LargeBlobInputs != nil {
		backend, largeBlobSupport, largeBlobKeyRequested, err = validateCreateLargeBlob(
			d.info,
			extInputs.LargeBlobInputs,
			options,
		)
		if err != nil {
			return protocol.AuthenticatorMakeCredentialResponse{}, err
		}

		switch backend {
		case largeBlobBackendDirect:
			extensions.CreateLargeBlobInput = protocol.CreateLargeBlobInput{
				LargeBlob: protocol.CreateLargeBlobParams{Support: largeBlobSupport},
			}
		case largeBlobBackendLegacy:
			if largeBlobKeyRequested {
				extensions.CreateLargeBlobKeyInput = protocol.CreateLargeBlobKeyInput{LargeBlobKey: true}
			}
		}
	}

	// hmac-secret
	if extInputs.CreateHMACSecretInputs != nil && extInputs.HMACCreateSecret {
		if !slices.Contains(d.info.Extensions, extension.ExtensionIdentifierHMACSecret) {
			return protocol.AuthenticatorMakeCredentialResponse{}, &ErrorWithMessage{Err: ErrNotSupported, Message: "device doesn't support hmac-secret extension"}
		}

		extensions.CreateHMACSecretInput = protocol.CreateHMACSecretInput{
			HMACSecret: extInputs.HMACCreateSecret,
		}
	}

	// hmac-secret-mc
	if extInputs.CreateHMACSecretMCInputs != nil {
		if err := validateHMACSecretMCSupport(d.info); err != nil {
			return protocol.AuthenticatorMakeCredentialResponse{}, err
		}

		if err := validateHMACGetSecretSalts(extInputs.HMACGetSecret); err != nil {
			return protocol.AuthenticatorMakeCredentialResponse{}, err
		}

		var (
			err          error
			keyAgreement cose.Key
		)

		pinUvAuthProtocol, keyAgreement, err = d.pinUvAuthProtocolWithKeyAgreement(ctx)
		if err != nil {
			return protocol.AuthenticatorMakeCredentialResponse{}, err
		}

		salt := slices.Concat(
			extInputs.HMACGetSecret.Salt1,
			extInputs.HMACGetSecret.Salt2,
		)

		pinProtocol, err = crypto.NewPinUvAuthProtocol(pinUvAuthProtocol)
		if err != nil {
			return protocol.AuthenticatorMakeCredentialResponse{}, err
		}

		var platformCoseKey cose.Key

		platformCoseKey, sharedSecret, err = pinProtocol.Encapsulate(keyAgreement)
		if err != nil {
			return protocol.AuthenticatorMakeCredentialResponse{}, err
		}

		saltEnc, err := pinProtocol.Encrypt(sharedSecret, salt)
		if err != nil {
			return protocol.AuthenticatorMakeCredentialResponse{}, err
		}

		saltAuth := crypto.Authenticate(
			pinUvAuthProtocol,
			sharedSecret,
			saltEnc,
		)

		extensions.CreateHMACSecretInput = protocol.CreateHMACSecretInput{
			HMACSecret: true,
		}
		extensions.CreateHMACSecretMCInput = protocol.CreateHMACSecretMCInput{
			HMACSecret: newHMACSecretInput(platformCoseKey, saltEnc, saltAuth, pinUvAuthProtocol),
		}
	}

	// prf
	if extInputs.PRFInputs != nil && slices.Contains(d.info.Extensions, extension.ExtensionIdentifierHMACSecret) {
		extensions.CreateHMACSecretInput = protocol.CreateHMACSecretInput{
			HMACSecret: true,
		}

		if createPRFEvaluation != nil {
			var (
				err          error
				keyAgreement cose.Key
			)

			pinUvAuthProtocol, keyAgreement, err = d.pinUvAuthProtocolWithKeyAgreement(ctx)
			if err != nil {
				return protocol.AuthenticatorMakeCredentialResponse{}, err
			}

			salt := prfSalts(*createPRFEvaluation)

			pinProtocol, err = crypto.NewPinUvAuthProtocol(pinUvAuthProtocol)
			if err != nil {
				return protocol.AuthenticatorMakeCredentialResponse{}, err
			}

			var platformCoseKey cose.Key

			platformCoseKey, sharedSecret, err = pinProtocol.Encapsulate(keyAgreement)
			if err != nil {
				return protocol.AuthenticatorMakeCredentialResponse{}, err
			}

			saltEnc, err := pinProtocol.Encrypt(sharedSecret, salt)
			if err != nil {
				return protocol.AuthenticatorMakeCredentialResponse{}, err
			}

			saltAuth := crypto.Authenticate(
				pinUvAuthProtocol,
				sharedSecret,
				saltEnc,
			)

			extensions.CreateHMACSecretMCInput = protocol.CreateHMACSecretMCInput{
				HMACSecret: newHMACSecretInput(platformCoseKey, saltEnc, saltAuth, pinUvAuthProtocol),
			}
		}
	}

	// credProtection
	if extInputs.CreateCredentialProtectionInputs != nil {
		credProtect, err := credentialProtectionValue(extInputs.CredentialProtectionPolicy)
		if err != nil {
			return protocol.AuthenticatorMakeCredentialResponse{}, err
		}

		if extInputs.EnforceCredentialProtectionPolicy &&
			extInputs.CredentialProtectionPolicy != extension.CredentialProtectionPolicyUserVerificationOptional &&
			!slices.Contains(d.info.Extensions, extension.ExtensionIdentifierCredentialProtection) {
			return protocol.AuthenticatorMakeCredentialResponse{}, &ErrorWithMessage{Err: ErrNotSupported, Message: "device doesn't support credProtect extension"}
		}

		extensions.CreateCredProtectInput = protocol.CreateCredProtectInput{
			CredProtect: credProtect,
		}
	}

	// credBlob
	if extInputs.CreateCredentialBlobInputs != nil {
		maxCredBlobLength, err := validateCredentialBlobSupport(d.info)
		if err != nil {
			return protocol.AuthenticatorMakeCredentialResponse{}, err
		}

		if uint(len(extInputs.CredBlob)) <= maxCredBlobLength {
			credBlob := extInputs.CredBlob
			if credBlob == nil {
				credBlob = []byte{}
			}

			extensions.CreateCredBlobInput = protocol.CreateCredBlobInput{
				CredBlob: credBlob,
			}
		}
	}

	// minPinLength
	if extInputs.CreateMinPinLengthInputs != nil && extInputs.MinPinLength {
		if !slices.Contains(d.info.Extensions, extension.ExtensionIdentifierMinPinLength) {
			return protocol.AuthenticatorMakeCredentialResponse{}, &ErrorWithMessage{Err: ErrNotSupported, Message: "device doesn't support minPinLength extension"}
		}

		extensions.CreateMinPinLengthInput = protocol.CreateMinPinLengthInput{
			MinPinLength: extInputs.MinPinLength,
		}
	}

	if extInputs.CreatePinComplexityPolicyInputs != nil && extInputs.PinComplexityPolicy {
		if !slices.Contains(d.info.Extensions, extension.ExtensionIdentifierPinComplexityPolicy) {
			return protocol.AuthenticatorMakeCredentialResponse{}, &ErrorWithMessage{Err: ErrNotSupported, Message: "device doesn't support pinComplexityPolicy extension"}
		}

		extensions.CreatePinComplexityPolicyInput = protocol.CreatePinComplexityPolicyInput{
			PinComplexityPolicy: extInputs.PinComplexityPolicy,
		}
	}

	// thirdPartyPayment
	if extInputs.PaymentInputs != nil && extInputs.Payment.IsPayment {
		if !slices.Contains(d.info.Extensions, extension.ExtensionIdentifierThirdPartyPayment) {
			return protocol.AuthenticatorMakeCredentialResponse{}, &ErrorWithMessage{Err: ErrNotSupported, Message: "device doesn't support thirdPartyPayment extension"}
		}

		extensions.CreateThirdPartyPaymentInput = protocol.CreateThirdPartyPaymentInput{
			ThirdPartyPayment: true,
		}
	}

	// previewSign
	var createPreviewSignInput *protocol.PreviewSignGenerateKeyInput
	if extInputs.PreviewSignInputs != nil {
		createPreviewSignInput, err = validateCreatePreviewSign(
			d.info,
			pinUvAuthToken,
			extInputs.PreviewSignInputs,
			options,
		)
		if err != nil {
			return protocol.AuthenticatorMakeCredentialResponse{}, err
		}

		extensions.CreatePreviewSignInput = protocol.CreatePreviewSignInput{
			PreviewSign: *createPreviewSignInput,
		}
	}

	clientDataHash := sha256.Sum256(clientData)

	resp, err := d.ctapClient.MakeCredential(
		ctx,
		pinUvAuthProtocol,
		pinUvAuthToken,
		clientDataHash[:],
		rp,
		user,
		pubKeyCredParams,
		excludeList,
		extensions,
		options,
		enterpriseAttestation,
		attestationFormatsPreference,
	)
	if err != nil {
		return protocol.AuthenticatorMakeCredentialResponse{}, err
	}

	if options[protocol.OptionResidentKeys] {
		d.invalidateInfoLocked()
	}

	extOutputs := new(webauthn.CreateAuthenticationExtensionsClientOutputs)
	resp.ExtensionOutputs = extOutputs

	// largeBlob
	largeBlobOutput, err := createLargeBlobOutput(
		backend,
		largeBlobSupport,
		largeBlobKeyRequested,
		resp,
	)
	if err != nil {
		return protocol.AuthenticatorMakeCredentialResponse{}, err
	}

	extOutputs.LargeBlobOutputs = largeBlobOutput
	if extInputs.PRFInputs != nil {
		extOutputs.CreatePRFOutputs = &webauthn.CreatePRFOutputs{}
	}

	if extInputs.CreateCredentialPropertiesInputs != nil && extInputs.CredentialProperties {
		extOutputs.CreateCredentialPropertiesOutputs = &webauthn.CreateCredentialPropertiesOutputs{
			CredentialProperties: webauthn.CredentialPropertiesOutput{
				ResidentKey: new(options[protocol.OptionResidentKeys]),
			},
		}
	}

	var authenticatorExtensions *protocol.CreateExtensionOutputs
	if resp.AuthData.Flags.ExtensionDataIncluded() {
		authenticatorExtensions = resp.AuthData.Extensions
	}

	if err := validateMakeCredentialExtensionOutputs(extensions, extInputs, authenticatorExtensions); err != nil {
		return protocol.AuthenticatorMakeCredentialResponse{}, err
	}

	// previewSign
	previewSignOutput, err := createPreviewSignOutput(createPreviewSignInput, resp)
	if err != nil {
		return protocol.AuthenticatorMakeCredentialResponse{}, err
	}

	extOutputs.PreviewSignOutputs = previewSignOutput

	if authenticatorExtensions == nil {
		return resp, nil
	}

	// credBlob
	if authenticatorExtensions.CreateCredBlobOutput != nil {
		extOutputs.CreateCredentialBlobOutputs = &webauthn.CreateCredentialBlobOutputs{
			CredBlob: authenticatorExtensions.CredBlob,
		}
	}

	// hmac-secret
	if authenticatorExtensions.CreateHMACSecretOutput != nil {
		if extInputs.CreateHMACSecretInputs != nil && extInputs.HMACCreateSecret {
			extOutputs.CreateHMACSecretOutputs = &webauthn.CreateHMACSecretOutputs{
				HMACCreateSecret: authenticatorExtensions.CreateHMACSecretOutput.HMACSecret,
			}
		}

		if extOutputs.CreatePRFOutputs != nil {
			extOutputs.PRF.Enabled = authenticatorExtensions.CreateHMACSecretOutput.HMACSecret
		}
	}

	// hmac-secret-mc
	if authenticatorExtensions.CreateHMACSecretMCOutput.HMACSecret != nil {
		if extInputs.PRFInputs != nil && !resp.AuthData.Flags.UserVerified() {
			return protocol.AuthenticatorMakeCredentialResponse{}, &ErrorWithMessage{Err: ErrSpecViolation, Message: "device returned PRF results without user verification"}
		}

		if extInputs.PRFInputs != nil &&
			(authenticatorExtensions.CreateHMACSecretOutput == nil ||
				!authenticatorExtensions.CreateHMACSecretOutput.HMACSecret) {
			return protocol.AuthenticatorMakeCredentialResponse{}, &ErrorWithMessage{Err: ErrSpecViolation, Message: "device returned PRF results for a credential without enabled hmac-secret"}
		}

		salt, err := pinProtocol.Decrypt(sharedSecret, authenticatorExtensions.CreateHMACSecretMCOutput.HMACSecret)
		if err != nil {
			return protocol.AuthenticatorMakeCredentialResponse{}, err
		}

		if createPRFEvaluation != nil {
			if err := validatePRFResultLength(*createPRFEvaluation, salt); err != nil {
				return protocol.AuthenticatorMakeCredentialResponse{}, err
			}
		}

		var output1, output2 []byte

		switch len(salt) {
		case 32:
			output1 = salt[:32]
		case 64:
			output1 = salt[:32]
			output2 = salt[32:]
		default:
			return protocol.AuthenticatorMakeCredentialResponse{}, &ErrorWithMessage{Err: ErrInvalidSaltSize, Message: "salt must be 32 or 64 bytes"}
		}

		if extInputs.PRFInputs != nil {
			extOutputs.PRF.Results = webauthn.AuthenticationExtensionsPRFValues{
				First:  output1,
				Second: output2,
			}
		} else {
			extOutputs.CreateHMACSecretMCOutputs = &webauthn.CreateHMACSecretMCOutputs{
				HMACGetSecret: webauthn.HMACGetSecretOutput{
					Output1: output1,
					Output2: output2,
				},
			}
		}
	}

	return resp, nil
}

// GetAssertion provides a generator function to iterate over assertions stored on the device
// for the specified Relying Party, clientData, and allowed list (in case of non-discoverable credentials).
// It yields results via a callback function.
func (d *Device) GetAssertion(
	ctx context.Context,
	pinUvAuthToken []byte,
	rpID string,
	clientData []byte,
	allowList []credential.PublicKeyCredentialDescriptor,
	extInputs *webauthn.GetAuthenticationExtensionsClientInputs,
	options map[protocol.Option]bool,
) iter.Seq2[protocol.AuthenticatorGetAssertionResponse, error] {
	return func(yield func(protocol.AuthenticatorGetAssertionResponse, error) bool) {
		d.mu.Lock()
		defer d.mu.Unlock()

		if err := d.ensureInfoLocked(ctx); err != nil {
			yield(protocol.AuthenticatorGetAssertionResponse{}, err)
			return
		}

		if extInputs == nil {
			extInputs = &webauthn.GetAuthenticationExtensionsClientInputs{}
		}

		if extInputs.PRFInputs != nil && extInputs.GetHMACSecretInputs != nil {
			yield(protocol.AuthenticatorGetAssertionResponse{}, &ErrorWithMessage{Err: SyntaxError, Message: "you cannot use hmac-secret and prf extensions at the same time"})
			return
		}

		getPRFEvaluation, err := validateGetPRF(d.info, pinUvAuthToken, allowList, extInputs, options)
		if err != nil {
			yield(protocol.AuthenticatorGetAssertionResponse{}, err)
			return
		}

		if err := validateGetAssertionAuthorization(d.info, pinUvAuthToken, options); err != nil {
			yield(protocol.AuthenticatorGetAssertionResponse{}, err)
			return
		}

		var (
			pinUvAuthProtocol protocol.PinUvAuthProtocol
			pinProtocol       *crypto.PinUvAuthProtocol
			sharedSecret      []byte
		)

		if pinUvAuthToken != nil {
			var err error

			pinUvAuthProtocol, err = d.pinUvAuthProtocolForRequest(pinUvAuthToken, true)
			if err != nil {
				yield(protocol.AuthenticatorGetAssertionResponse{}, err)
				return
			}
		}

		extensions := new(protocol.GetExtensionInputs)

		// largeBlob
		var (
			backend        largeBlobBackend
			largeBlobRead  bool
			largeBlobWrite []byte
		)
		if extInputs.LargeBlobInputs != nil {
			backend, largeBlobRead, largeBlobWrite, err = validateGetLargeBlob(
				d.info,
				extInputs.LargeBlobInputs,
				allowList,
			)
			if err != nil {
				yield(protocol.AuthenticatorGetAssertionResponse{}, err)
				return
			}

			switch backend {
			case largeBlobBackendDirect:
				params := protocol.GetLargeBlobParams{Read: largeBlobRead}

				if largeBlobWrite != nil {
					compressed, err := crypto.CompressLargeBlobData(largeBlobWrite)
					if err != nil {
						yield(protocol.AuthenticatorGetAssertionResponse{}, err)
						return
					}

					originalSize := uint(len(largeBlobWrite))
					params.Write = compressed
					params.OriginalSize = &originalSize
				}

				extensions.GetLargeBlobInput = protocol.GetLargeBlobInput{LargeBlob: params}
			case largeBlobBackendLegacy:
				extensions.GetLargeBlobKeyInput = protocol.GetLargeBlobKeyInput{LargeBlobKey: true}
			}
		}

		// hmac-secret
		if extInputs.GetHMACSecretInputs != nil {
			if err := validateHMACSecretUserPresence(options); err != nil {
				yield(protocol.AuthenticatorGetAssertionResponse{}, err)
				return
			}

			if !slices.Contains(d.info.Extensions, extension.ExtensionIdentifierHMACSecret) {
				yield(protocol.AuthenticatorGetAssertionResponse{}, &ErrorWithMessage{Err: ErrNotSupported, Message: "device doesn't support hmac-secret extension"})
				return
			}

			if err := validateHMACGetSecretSalts(extInputs.HMACGetSecret); err != nil {
				yield(protocol.AuthenticatorGetAssertionResponse{}, err)
				return
			}

			var (
				err          error
				keyAgreement cose.Key
			)

			pinUvAuthProtocol, keyAgreement, err = d.pinUvAuthProtocolWithKeyAgreement(ctx)
			if err != nil {
				yield(protocol.AuthenticatorGetAssertionResponse{}, err)
				return
			}

			salt := slices.Concat(
				extInputs.HMACGetSecret.Salt1,
				extInputs.HMACGetSecret.Salt2,
			)

			pinProtocol, err = crypto.NewPinUvAuthProtocol(pinUvAuthProtocol)
			if err != nil {
				yield(protocol.AuthenticatorGetAssertionResponse{}, err)
				return
			}

			var platformCoseKey cose.Key

			platformCoseKey, sharedSecret, err = pinProtocol.Encapsulate(keyAgreement)
			if err != nil {
				yield(protocol.AuthenticatorGetAssertionResponse{}, err)
				return
			}

			saltEnc, err := pinProtocol.Encrypt(sharedSecret, salt)
			if err != nil {
				yield(protocol.AuthenticatorGetAssertionResponse{}, err)
				return
			}

			saltAuth := crypto.Authenticate(
				pinUvAuthProtocol,
				sharedSecret,
				saltEnc,
			)

			extensions.GetHMACSecretInput = protocol.GetHMACSecretInput{
				HMACSecret: newHMACSecretInput(platformCoseKey, saltEnc, saltAuth, pinUvAuthProtocol),
			}
		}

		// prf
		if getPRFEvaluation != nil {
			var (
				err          error
				keyAgreement cose.Key
			)

			pinUvAuthProtocol, keyAgreement, err = d.pinUvAuthProtocolWithKeyAgreement(ctx)
			if err != nil {
				yield(protocol.AuthenticatorGetAssertionResponse{}, err)
				return
			}

			salt := prfSalts(*getPRFEvaluation)

			pinProtocol, err = crypto.NewPinUvAuthProtocol(pinUvAuthProtocol)
			if err != nil {
				yield(protocol.AuthenticatorGetAssertionResponse{}, err)
				return
			}

			var platformCoseKey cose.Key

			platformCoseKey, sharedSecret, err = pinProtocol.Encapsulate(keyAgreement)
			if err != nil {
				yield(protocol.AuthenticatorGetAssertionResponse{}, err)
				return
			}

			saltEnc, err := pinProtocol.Encrypt(sharedSecret, salt)
			if err != nil {
				yield(protocol.AuthenticatorGetAssertionResponse{}, err)
				return
			}

			saltAuth := crypto.Authenticate(
				pinUvAuthProtocol,
				sharedSecret,
				saltEnc,
			)

			extensions.GetHMACSecretInput = protocol.GetHMACSecretInput{
				HMACSecret: newHMACSecretInput(platformCoseKey, saltEnc, saltAuth, pinUvAuthProtocol),
			}
		}

		// credBlob
		if extInputs.GetCredentialBlobInputs != nil && extInputs.GetCredBlob {
			if _, err := validateCredentialBlobSupport(d.info); err != nil {
				yield(protocol.AuthenticatorGetAssertionResponse{}, err)
				return
			}

			extensions.GetCredBlobInput = protocol.GetCredBlobInput{
				CredBlob: extInputs.GetCredBlob,
			}
		}

		// thirdPartyPayment
		if extInputs.PaymentInputs != nil && extInputs.Payment.IsPayment {
			if !slices.Contains(d.info.Extensions, extension.ExtensionIdentifierThirdPartyPayment) {
				yield(protocol.AuthenticatorGetAssertionResponse{}, &ErrorWithMessage{Err: ErrNotSupported, Message: "device doesn't support thirdPartyPayment extension"})
				return
			}

			extensions.GetThirdPartyPaymentInput = protocol.GetThirdPartyPaymentInput{
				ThirdPartyPayment: true,
			}
		}

		// previewSign
		var getPreviewSignInput *protocol.PreviewSignSignInput
		if extInputs.PreviewSignInputs != nil {
			getPreviewSignInput, err = validateGetPreviewSign(d.info, allowList, extInputs.PreviewSignInputs)
			if err != nil {
				yield(protocol.AuthenticatorGetAssertionResponse{}, err)
				return
			}

			extensions.GetPreviewSignInput = protocol.GetPreviewSignInput{
				PreviewSign: *getPreviewSignInput,
			}
		}

		// largeBlob (legacy)
		var legacyAssertions []protocol.AuthenticatorGetAssertionResponse

		emitAssertion := func(assertion protocol.AuthenticatorGetAssertionResponse) bool {
			if backend == largeBlobBackendLegacy {
				legacyAssertions = append(legacyAssertions, assertion)
				return true
			}

			return yield(assertion, nil)
		}

		clientDataHash := sha256.Sum256(clientData)
		for assertion, err := range d.ctapClient.GetAssertion(
			ctx,
			pinUvAuthProtocol,
			pinUvAuthToken,
			rpID,
			clientDataHash[:],
			allowList,
			extensions,
			options,
		) {
			if err != nil {
				yield(protocol.AuthenticatorGetAssertionResponse{}, err)
				return
			}

			assertion.ExtensionOutputs = new(webauthn.GetAuthenticationExtensionsClientOutputs)
			if extInputs.PRFInputs != nil {
				assertion.ExtensionOutputs.GetPRFOutputs = &webauthn.GetPRFOutputs{}
			}

			// largeBlob
			largeBlobOutput, err := getLargeBlobOutput(
				backend,
				largeBlobRead,
				largeBlobWrite,
				assertion,
			)
			if err != nil {
				yield(protocol.AuthenticatorGetAssertionResponse{}, err)
				return
			}

			assertion.ExtensionOutputs.LargeBlobOutputs = largeBlobOutput

			var authenticatorExtensions *protocol.GetExtensionOutputs
			if assertion.AuthData.Flags.ExtensionDataIncluded() {
				authenticatorExtensions = assertion.AuthData.Extensions
			}

			if err := validateGetAssertionExtensionOutputs(extensions, authenticatorExtensions); err != nil {
				yield(protocol.AuthenticatorGetAssertionResponse{}, err)
				return
			}

			// previewSign
			previewSignOutput, err := getPreviewSignOutput(getPreviewSignInput, assertion)
			if err != nil {
				yield(protocol.AuthenticatorGetAssertionResponse{}, err)
				return
			}

			assertion.ExtensionOutputs.PreviewSignOutputs = previewSignOutput

			// Yield assertions without extension data
			if authenticatorExtensions == nil {
				if !emitAssertion(assertion) {
					return
				}

				continue
			}

			// credBlob
			if authenticatorExtensions.CredBlob != nil {
				assertion.ExtensionOutputs.GetCredentialBlobOutputs = &webauthn.GetCredentialBlobOutputs{
					GetCredBlob: authenticatorExtensions.CredBlob,
				}
			}

			// hmac-secret or prf
			if authenticatorExtensions.HMACSecret != nil {
				if extInputs.PRFInputs != nil && !assertion.AuthData.Flags.UserVerified() {
					yield(protocol.AuthenticatorGetAssertionResponse{}, &ErrorWithMessage{Err: ErrSpecViolation, Message: "device returned PRF results without user verification"})
					return
				}

				salt, err := pinProtocol.Decrypt(sharedSecret, authenticatorExtensions.HMACSecret)
				if err != nil {
					yield(protocol.AuthenticatorGetAssertionResponse{}, err)
					return
				}

				if getPRFEvaluation != nil {
					if err := validatePRFResultLength(*getPRFEvaluation, salt); err != nil {
						yield(protocol.AuthenticatorGetAssertionResponse{}, err)
						return
					}
				}

				switch len(salt) {
				case 32:
					if extInputs.GetHMACSecretInputs != nil {
						assertion.ExtensionOutputs.GetHMACSecretOutputs = &webauthn.GetHMACSecretOutputs{
							HMACGetSecret: webauthn.HMACGetSecretOutput{
								Output1: salt[:32],
							},
						}
					}

					if extInputs.PRFInputs != nil {
						assertion.ExtensionOutputs.GetPRFOutputs = &webauthn.GetPRFOutputs{
							PRF: webauthn.GetAuthenticationExtensionsPRFOutputs{
								Results: webauthn.AuthenticationExtensionsPRFValues{
									First: salt[:32],
								},
							},
						}
					}
				case 64:
					if extInputs.GetHMACSecretInputs != nil {
						assertion.ExtensionOutputs.GetHMACSecretOutputs = &webauthn.GetHMACSecretOutputs{
							HMACGetSecret: webauthn.HMACGetSecretOutput{
								Output1: salt[:32],
								Output2: salt[32:],
							},
						}
					}

					if extInputs.PRFInputs != nil {
						assertion.ExtensionOutputs.GetPRFOutputs = &webauthn.GetPRFOutputs{
							PRF: webauthn.GetAuthenticationExtensionsPRFOutputs{
								Results: webauthn.AuthenticationExtensionsPRFValues{
									First:  salt[:32],
									Second: salt[32:],
								},
							},
						}
					}
				default:
					yield(protocol.AuthenticatorGetAssertionResponse{}, &ErrorWithMessage{Err: ErrInvalidSaltSize, Message: "salt must be 32 or 64 bytes"})
					return
				}
			}

			if !emitAssertion(assertion) {
				return
			}
		}

		// largeBlobKey (technically legacy)
		if backend == largeBlobBackendLegacy {
			largeBlobOutputs, err := d.resolveLegacyLargeBlobOutputs(
				ctx,
				pinUvAuthToken,
				largeBlobRead,
				largeBlobWrite,
				legacyAssertions,
			)
			if err != nil {
				yield(protocol.AuthenticatorGetAssertionResponse{}, err)
				return
			}

			for i := range legacyAssertions {
				legacyAssertions[i].ExtensionOutputs.LargeBlobOutputs = largeBlobOutputs[i]
				if !yield(legacyAssertions[i], nil) {
					return
				}
			}
		}
	}
}

// GetInfo retrieves current metadata and capabilities from the device.
func (d *Device) GetInfo(ctx context.Context) (protocol.AuthenticatorGetInfoResponse, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	return d.refreshInfoLocked(ctx)
}

// GetInfoCached returns the last authenticator metadata snapshot and whether
// it is still valid. It never communicates with the authenticator.
func (d *Device) GetInfoCached() (protocol.AuthenticatorGetInfoResponse, bool) {
	d.infoMu.RLock()
	defer d.infoMu.RUnlock()

	return d.info, d.infoValid
}

// Vendor exchanges one CTAPHID vendor command on the authenticator's allocated
// channel. It is unavailable for transports other than CTAPHID.
func (d *Device) Vendor(
	ctx context.Context,
	command ctaphid.Command,
	data []byte,
) (ctaphid.VendorResponse, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	transport, ok := d.transport.(interface {
		Vendor(context.Context, ctaphid.Command, []byte) (ctaphid.VendorResponse, error)
	})
	if !ok {
		return ctaphid.VendorResponse{}, &ErrorWithMessage{Err: ErrNotSupported, Message: "vendor commands require CTAPHID"}
	}

	return transport.Vendor(ctx, command, data)
}

// GetPINRetries retrieves the number of PIN retries remaining for the device, and if it requires a power cycle
// (after reaching the limit, you can reset remaining tries by re-connecting the token).
func (d *Device) GetPINRetries(ctx context.Context) (uint, *bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if err := d.ensureInfoLocked(ctx); err != nil {
		return 0, nil, err
	}

	_, ok := d.info.Options[protocol.OptionClientPIN]
	if !ok {
		return 0, nil, &ErrorWithMessage{Err: ErrNotSupported, Message: "device doesn't support clientPin option"}
	}

	pinUvAuthProtocol, err := d.requirePinUvAuthProtocol()
	if err != nil {
		return 0, nil, err
	}

	return d.ctapClient.GetPINRetries(ctx, pinUvAuthProtocol)
}

// GetUVRetries retrieves the number of remaining user verification retries from the device.
// Returns an error if the device does not support user verification.
func (d *Device) GetUVRetries(ctx context.Context) (uint, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if err := d.ensureInfoLocked(ctx); err != nil {
		return 0, err
	}

	if isFIDO20Only(d.info.Versions) {
		return 0, &ErrorWithMessage{Err: ErrNotSupported, Message: "getUVRetries requires CTAP 2.1 or later"}
	}

	_, ok := d.info.Options[protocol.OptionUserVerification]
	if !ok {
		return 0, &ErrorWithMessage{Err: ErrNotSupported, Message: "device doesn't support user verification"}
	}

	var (
		pinUvAuthProtocol protocol.PinUvAuthProtocol
		err               error
	)
	if len(d.info.PinUvAuthProtocols) > 0 {
		pinUvAuthProtocol, err = d.requirePinUvAuthProtocol()
		if err != nil {
			return 0, err
		}
	}

	return d.ctapClient.GetUVRetries(ctx, pinUvAuthProtocol)
}

// SetPIN sets a new PIN on the device if the clientPin option is supported and no PIN exists.
// Returns an error if the device does not support clientPin or if it was already set with PIN.
func (d *Device) SetPIN(ctx context.Context, pin string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if err := d.ensureInfoLocked(ctx); err != nil {
		return err
	}

	clientPin, ok := d.info.Options[protocol.OptionClientPIN]
	if !ok {
		return &ErrorWithMessage{Err: ErrNotSupported, Message: "device doesn't support clientPin option"}
	}

	if clientPin {
		return &ErrorWithMessage{Err: ErrPinAlreadySet, Message: "pin already set, use changePin instead"}
	}

	pin, err := d.normalizeAndValidateNewPIN(pin)
	if err != nil {
		return err
	}

	pinUvAuthProtocol, keyAgreement, err := d.pinUvAuthProtocolWithKeyAgreement(ctx)
	if err != nil {
		return err
	}

	if err := d.ctapClient.SetPIN(ctx, pinUvAuthProtocol, keyAgreement, pin); err != nil {
		return d.pinPolicyError(err)
	}

	d.invalidateInfoLocked()

	return nil
}

// ChangePIN updates the device's PIN by using the provided current PIN and new PIN.
// Returns an error if the device does not support clientPin or if the PIN change process fails.
func (d *Device) ChangePIN(ctx context.Context, currentPin, newPin string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if err := d.ensureInfoLocked(ctx); err != nil {
		return err
	}

	clientPin, ok := d.info.Options[protocol.OptionClientPIN]
	if !ok {
		return &ErrorWithMessage{Err: ErrNotSupported, Message: "device doesn't support clientPin option"}
	}

	if !clientPin {
		return &ErrorWithMessage{Err: ErrPinNotSet, Message: "please set PIN first"}
	}

	currentPin, err := d.normalizeAndValidateCurrentPIN(currentPin)
	if err != nil {
		return err
	}

	newPin, err = d.normalizeAndValidateNewPIN(newPin)
	if err != nil {
		return err
	}

	pinUvAuthProtocol, keyAgreement, err := d.pinUvAuthProtocolWithKeyAgreement(ctx)
	if err != nil {
		return err
	}

	if err := d.ctapClient.ChangePIN(
		ctx,
		pinUvAuthProtocol,
		keyAgreement,
		currentPin,
		newPin,
	); err != nil {
		return d.pinPolicyError(err)
	}

	d.invalidateInfoLocked()

	return nil
}

// GetPinUvAuthTokenUsingPIN obtains a pinUvAuthToken using a given PIN, permission, and in some cases optional
// Relying Party ID. Returns a token as a byte slice or an error if the operation fails.
// Checks device capabilities and permissions before proceeding.
func (d *Device) GetPinUvAuthTokenUsingPIN(
	ctx context.Context,
	pin string,
	permission protocol.Permission,
	rpID string,
) ([]byte, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if err := d.ensureInfoLocked(ctx); err != nil {
		return nil, err
	}

	if d.info.ForcePINChange {
		message := "change PIN before obtaining a pinUvAuthToken"
		if len(d.info.PinComplexityPolicyURL) != 0 {
			message += "; PIN policy details: " + d.info.PinComplexityPolicyURLString()
		}

		return nil, &ErrorWithMessage{Err: ErrPinChangeRequired, Message: message}
	}

	pin, err := d.normalizeAndValidateCurrentPIN(pin)
	if err != nil {
		return nil, err
	}

	flow, err := selectPinTokenFlowUsingPIN(d.info, permission, rpID)
	if err != nil {
		return nil, err
	}

	pinUvAuthProtocol, keyAgreement, err := d.pinUvAuthProtocolWithKeyAgreement(ctx)
	if err != nil {
		return nil, err
	}

	switch flow {
	case pinTokenFlowLegacy:
		return d.ctapClient.GetPinToken(
			ctx,
			pinUvAuthProtocol,
			keyAgreement,
			pin,
		)
	case pinTokenFlowWithPermissions:
		return d.ctapClient.GetPinUvAuthTokenUsingPinWithPermissions(
			ctx,
			pinUvAuthProtocol,
			keyAgreement,
			pin,
			permission,
			rpID,
		)
	default:
		return nil, &ErrorWithMessage{Err: ErrSpecViolation, Message: "invalid PIN token flow"}
	}
}

// GetPinUvAuthTokenUsingUV obtains a pinUvAuthToken by performing user verification (UV) on a compatible device.
// It supports both the legacy FIDO_2_1_PRE uvToken flow and the permissioned CTAP 2.1 flow.
func (d *Device) GetPinUvAuthTokenUsingUV(ctx context.Context, permission protocol.Permission, rpID string) ([]byte, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if err := d.ensureInfoLocked(ctx); err != nil {
		return nil, err
	}

	flow, err := selectPinUvAuthTokenFlowUsingUV(d.info, permission, rpID)
	if err != nil {
		return nil, err
	}

	switch flow {
	case uvTokenFlowPreview:
		keyAgreement, err := d.ctapClient.GetKeyAgreement(ctx, protocol.PinUvAuthProtocolOne)
		if err != nil {
			return nil, err
		}

		return d.ctapClient.GetPinUvAuthTokenUsingUv(ctx, keyAgreement)
	case uvTokenFlowWithPermissions:
		pinUvAuthProtocol, keyAgreement, err := d.pinUvAuthProtocolWithKeyAgreement(ctx)
		if err != nil {
			return nil, err
		}

		return d.ctapClient.GetPinUvAuthTokenUsingUvWithPermissions(
			ctx,
			pinUvAuthProtocol,
			keyAgreement,
			permission,
			rpID,
		)
	default:
		return nil, &ErrorWithMessage{Err: ErrSpecViolation, Message: "invalid UV token flow"}
	}
}

// Reset performs a factory reset on the device, clearing all stored user data and resetting it to its default state.
// Some devices require doing reset within 10 seconds after you connected the token.
func (d *Device) Reset(ctx context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if err := d.ctapClient.Reset(ctx); err != nil {
		return err
	}

	d.invalidateInfoLocked()

	return nil
}

// GetBioModality returns bio modality of authenticator.
// Currently, only fingerprint modality is defined in the FIDO 2.2 specification.
func (d *Device) GetBioModality(ctx context.Context) (protocol.AuthenticatorBioEnrollmentResponse, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if err := d.ensureInfoLocked(ctx); err != nil {
		return protocol.AuthenticatorBioEnrollmentResponse{}, err
	}

	preview, err := bioEnrollmentMode(d.info)
	if err != nil {
		return protocol.AuthenticatorBioEnrollmentResponse{}, err
	}

	return d.ctapClient.GetBioModality(
		ctx,
		preview,
	)
}

// GetFingerprintSensorInfo returns three properties:
//
//		FingerprintKind: For touch type fingerprints, its value is 1. For swipe type fingerprints, its value is 2.
//		MaxCaptureSamplesRequiredForEnroll: Indicates the maximum good samples required for enrollment.
//	 	MaxTemplateFriendlyName: Indicates the maximum number of bytes the authenticator will accept as a templateFriendlyName.
func (d *Device) GetFingerprintSensorInfo(ctx context.Context) (protocol.AuthenticatorBioEnrollmentResponse, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if err := d.ensureInfoLocked(ctx); err != nil {
		return protocol.AuthenticatorBioEnrollmentResponse{}, err
	}

	preview, err := bioEnrollmentMode(d.info)
	if err != nil {
		return protocol.AuthenticatorBioEnrollmentResponse{}, err
	}

	return d.ctapClient.GetFingerprintSensorInfo(
		ctx,
		preview,
	)
}

// EnrollBegin begins a fingerprint enrollment process and returns TemplateID, LastEnrollSampleStatus,
// and RemainingSamples properties. Use those properties to continue to capture the next samples or cancel it.
func (d *Device) EnrollBegin(
	ctx context.Context,
	pinUvAuthToken []byte,
	timeoutMilliseconds uint,
) (protocol.AuthenticatorBioEnrollmentResponse, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if err := d.ensureInfoLocked(ctx); err != nil {
		return protocol.AuthenticatorBioEnrollmentResponse{}, err
	}

	preview, err := bioEnrollmentMode(d.info)
	if err != nil {
		return protocol.AuthenticatorBioEnrollmentResponse{}, err
	}

	pinUvAuthProtocol, err := d.pinUvAuthProtocolForRequest(pinUvAuthToken, true)
	if err != nil {
		return protocol.AuthenticatorBioEnrollmentResponse{}, err
	}

	resp, err := d.ctapClient.EnrollBegin(
		ctx,
		preview,
		pinUvAuthProtocol,
		pinUvAuthToken,
		timeoutMilliseconds,
	)
	if err != nil {
		return protocol.AuthenticatorBioEnrollmentResponse{}, err
	}

	if resp.RemainingSamples == nil {
		return protocol.AuthenticatorBioEnrollmentResponse{}, &ErrorWithMessage{Err: ErrSpecViolation, Message: "device must return remaining samples"}
	}

	if len(resp.TemplateID) > 0 && *resp.RemainingSamples == 0 {
		d.invalidateInfoLocked()
	}

	return resp, nil
}

// EnrollCaptureNextSample continues capturing samples from an already started enrollment process.
func (d *Device) EnrollCaptureNextSample(
	ctx context.Context,
	pinUvAuthToken []byte,
	templateID []byte,
	timeoutMilliseconds uint,
) (protocol.AuthenticatorBioEnrollmentResponse, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if err := d.ensureInfoLocked(ctx); err != nil {
		return protocol.AuthenticatorBioEnrollmentResponse{}, err
	}

	preview, err := bioEnrollmentMode(d.info)
	if err != nil {
		return protocol.AuthenticatorBioEnrollmentResponse{}, err
	}

	pinUvAuthProtocol, err := d.pinUvAuthProtocolForRequest(pinUvAuthToken, true)
	if err != nil {
		return protocol.AuthenticatorBioEnrollmentResponse{}, err
	}

	resp, err := d.ctapClient.EnrollCaptureNextSample(
		ctx,
		preview,
		pinUvAuthProtocol,
		pinUvAuthToken,
		templateID,
		timeoutMilliseconds,
	)
	if err != nil {
		return protocol.AuthenticatorBioEnrollmentResponse{}, err
	}

	if resp.RemainingSamples == nil {
		return protocol.AuthenticatorBioEnrollmentResponse{}, &ErrorWithMessage{Err: ErrSpecViolation, Message: "device must return remaining samples"}
	}

	if len(resp.TemplateID) > 0 && *resp.RemainingSamples == 0 {
		d.invalidateInfoLocked()
	}

	return resp, nil
}

// CancelCurrentEnrollment cancels a current enrollment process.
func (d *Device) CancelCurrentEnrollment(ctx context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if err := d.ensureInfoLocked(ctx); err != nil {
		return err
	}

	preview, err := bioEnrollmentMode(d.info)
	if err != nil {
		return err
	}

	return d.ctapClient.CancelCurrentEnrollment(
		ctx,
		preview,
	)
}

// EnumerateEnrollments enumerates enrollments by returning TemplateInfos property with an array of TemplateInfo
// for all the enrollments available on the authenticator.
func (d *Device) EnumerateEnrollments(ctx context.Context, pinUvAuthToken []byte) (protocol.AuthenticatorBioEnrollmentResponse, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if err := d.ensureInfoLocked(ctx); err != nil {
		return protocol.AuthenticatorBioEnrollmentResponse{}, err
	}

	preview, err := bioEnrollmentMode(d.info)
	if err != nil {
		return protocol.AuthenticatorBioEnrollmentResponse{}, err
	}

	pinUvAuthProtocol, err := d.pinUvAuthProtocolForRequest(pinUvAuthToken, true)
	if err != nil {
		return protocol.AuthenticatorBioEnrollmentResponse{}, err
	}

	return d.ctapClient.EnumerateEnrollments(
		ctx,
		preview,
		pinUvAuthProtocol,
		pinUvAuthToken,
	)
}

// SetFriendlyName allows renaming/setting of a friendly fingerprint name.
func (d *Device) SetFriendlyName(ctx context.Context, pinUvAuthToken []byte, templateID []byte, friendlyName string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if err := d.ensureInfoLocked(ctx); err != nil {
		return err
	}

	preview, err := bioEnrollmentMode(d.info)
	if err != nil {
		return err
	}

	pinUvAuthProtocol, err := d.pinUvAuthProtocolForRequest(pinUvAuthToken, true)
	if err != nil {
		return err
	}

	return d.ctapClient.SetFriendlyName(
		ctx,
		preview,
		pinUvAuthProtocol,
		pinUvAuthToken,
		templateID,
		friendlyName,
	)
}

// RemoveEnrollment removes existing enrollment.
func (d *Device) RemoveEnrollment(ctx context.Context, pinUvAuthToken []byte, templateID []byte) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if err := d.ensureInfoLocked(ctx); err != nil {
		return err
	}

	preview, err := bioEnrollmentMode(d.info)
	if err != nil {
		return err
	}

	pinUvAuthProtocol, err := d.pinUvAuthProtocolForRequest(pinUvAuthToken, true)
	if err != nil {
		return err
	}

	if err := d.ctapClient.RemoveEnrollment(
		ctx,
		preview,
		pinUvAuthProtocol,
		pinUvAuthToken,
		templateID,
	); err != nil {
		return err
	}

	d.invalidateInfoLocked()

	return nil
}

// GetCredsMetadata retrieves credential management metadata if the device supports it.
// Mainly ExistingResidentCredentialsCount and MaxPossibleRemainingResidentCredentialsCount.
func (d *Device) GetCredsMetadata(ctx context.Context, pinUvAuthToken []byte) (protocol.AuthenticatorCredentialManagementResponse, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if err := d.ensureInfoLocked(ctx); err != nil {
		return protocol.AuthenticatorCredentialManagementResponse{}, err
	}

	preview, err := credentialManagementMode(d.info)
	if err != nil {
		return protocol.AuthenticatorCredentialManagementResponse{}, err
	}

	pinUvAuthProtocol, err := d.pinUvAuthProtocolForRequest(pinUvAuthToken, true)
	if err != nil {
		return protocol.AuthenticatorCredentialManagementResponse{}, err
	}

	return d.ctapClient.GetCredsMetadata(
		ctx,
		preview,
		pinUvAuthProtocol,
		pinUvAuthToken,
	)
}

// EnumerateRPs provides a generator function to iterate over Relying Parties stored on the device.
// It utilizes the Credential Management extension and yields results via a callback function.
// If the device does not support credential management, an error is yielded.
//
// IMPORTANT: Fully consume this iterator before invoking any other Device
// method. Authenticators keep enumeration state internally, and Device holds
// its request mutex while yielding. In particular, collect all RPs first and
// only then call EnumerateCredentials; nesting the iterators will deadlock and
// would invalidate the authenticator's active enumeration state.
func (d *Device) EnumerateRPs(ctx context.Context, pinUvAuthToken []byte) iter.Seq2[protocol.AuthenticatorCredentialManagementResponse, error] {
	return func(yield func(protocol.AuthenticatorCredentialManagementResponse, error) bool) {
		d.mu.Lock()
		defer d.mu.Unlock()

		if err := d.ensureInfoLocked(ctx); err != nil {
			yield(protocol.AuthenticatorCredentialManagementResponse{}, err)
			return
		}

		preview, err := credentialManagementMode(d.info)
		if err != nil {
			yield(protocol.AuthenticatorCredentialManagementResponse{}, err)
			return
		}

		pinUvAuthProtocol, err := d.pinUvAuthProtocolForRequest(pinUvAuthToken, true)
		if err != nil {
			yield(protocol.AuthenticatorCredentialManagementResponse{}, err)
			return
		}

		for rp, err := range d.ctapClient.EnumerateRPs(
			ctx,
			preview,
			pinUvAuthProtocol,
			pinUvAuthToken,
		) {
			if !yield(rp, err) {
				return
			}
		}
	}
}

// EnumerateCredentials provides a generator function to iterate over Credentials stored on the device
// for the specified Relying Party. It utilizes the Credential Management extension and yields results
// via a callback function. If the device does not support credential management, an error is yielded.
//
// IMPORTANT: Fully consume this iterator before invoking any other Device
// method. Authenticators keep enumeration state internally, and Device holds
// its request mutex while yielding. Do not nest this iterator inside
// EnumerateRPs; finish and materialize the RP enumeration first.
func (d *Device) EnumerateCredentials(ctx context.Context, pinUvAuthToken []byte, rpIDHash []byte) iter.Seq2[protocol.AuthenticatorCredentialManagementResponse, error] {
	return func(yield func(protocol.AuthenticatorCredentialManagementResponse, error) bool) {
		d.mu.Lock()
		defer d.mu.Unlock()

		if err := d.ensureInfoLocked(ctx); err != nil {
			yield(protocol.AuthenticatorCredentialManagementResponse{}, err)
			return
		}

		preview, err := credentialManagementMode(d.info)
		if err != nil {
			yield(protocol.AuthenticatorCredentialManagementResponse{}, err)
			return
		}

		pinUvAuthProtocol, err := d.pinUvAuthProtocolForRequest(pinUvAuthToken, true)
		if err != nil {
			yield(protocol.AuthenticatorCredentialManagementResponse{}, err)
			return
		}

		for rp, err := range d.ctapClient.EnumerateCredentials(
			ctx,
			preview,
			pinUvAuthProtocol,
			pinUvAuthToken,
			rpIDHash,
		) {
			if !yield(rp, err) {
				return
			}
		}
	}
}

// DeleteCredential removes a specified credential from the device using the given authentication token.
// It returns an error if credential management is not supported or the operation fails.
func (d *Device) DeleteCredential(
	ctx context.Context,
	pinUvAuthToken []byte,
	credentialID credential.PublicKeyCredentialDescriptor,
) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if err := d.ensureInfoLocked(ctx); err != nil {
		return err
	}

	preview, err := credentialManagementMode(d.info)
	if err != nil {
		return err
	}

	pinUvAuthProtocol, err := d.pinUvAuthProtocolForRequest(pinUvAuthToken, true)
	if err != nil {
		return err
	}

	if err := d.ctapClient.DeleteCredential(
		ctx,
		preview,
		pinUvAuthProtocol,
		pinUvAuthToken,
		credentialID,
	); err != nil {
		return err
	}

	d.invalidateInfoLocked()

	return nil
}

// UpdateUserInformation updates information of an existing user credential on the device.
// Requires the device to support credential management features.
// Returns an error if the operation is not supported or fails.
func (d *Device) UpdateUserInformation(
	ctx context.Context,
	pinUvAuthToken []byte,
	credentialID credential.PublicKeyCredentialDescriptor,
	user credential.PublicKeyCredentialUserEntity,
) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if err := d.ensureInfoLocked(ctx); err != nil {
		return err
	}

	preview, err := credentialManagementMode(d.info)
	if err != nil {
		return err
	}

	pinUvAuthProtocol, err := d.pinUvAuthProtocolForRequest(pinUvAuthToken, true)
	if err != nil {
		return err
	}

	if err := d.ctapClient.UpdateUserInformation(
		ctx,
		preview,
		pinUvAuthProtocol,
		pinUvAuthToken,
		credentialID,
		user,
	); err != nil {
		return err
	}

	d.invalidateInfoLocked()

	return nil
}

// Selection is a higher-level version of ctap.Selection. CTAPHID commands are
// canceled when the context is canceled; other transports check the context
// before starting the command.
func (d *Device) Selection(ctx context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if err := d.ensureInfoLocked(ctx); err != nil {
		return err
	}

	if isFIDO20Only(d.info.Versions) {
		return &ErrorWithMessage{Err: ErrNotSupported, Message: "authenticatorSelection requires CTAP 2.1 or later"}
	}

	return d.ctapClient.Selection(ctx)
}

// GetLargeBlobs retrieves a list of large blobs from the device that supports the large blobs option.
// Returns an error if the device does not support large blobs or if there is an issue with the retrieval process.
// Ensures integrity by validating computed and actual hashes of the retrieved data.
func (d *Device) GetLargeBlobs(ctx context.Context) ([]protocol.LargeBlob, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if err := d.ensureInfoLocked(ctx); err != nil {
		return nil, err
	}

	return d.getLargeBlobsLocked(ctx)
}

func (d *Device) getLargeBlobsLocked(ctx context.Context) ([]protocol.LargeBlob, error) {
	largeBlobs, ok := d.info.Options[protocol.OptionLargeBlobs]
	if !ok || !largeBlobs {
		return nil, &ErrorWithMessage{Err: ErrNotSupported, Message: "device doesn't support largeBlobs"}
	}

	maxFragmentLength := d.maxFragmentLength()

	resp, err := d.ctapClient.LargeBlobs(
		ctx,
		0,
		nil,
		maxFragmentLength,
		nil,
		0,
		0,
	)
	if err != nil {
		return nil, err
	}

	fragment := resp.Config
	config := fragment
	offset := uint(len(fragment))

	// Continue to read
	for uint(len(fragment)) == maxFragmentLength {
		respNext, err := d.ctapClient.LargeBlobs(
			ctx,
			0,
			nil,
			maxFragmentLength,
			nil,
			offset,
			0,
		)
		if err != nil {
			return nil, err
		}

		fragment = respNext.Config
		config = append(config, fragment...)
		offset += uint(len(fragment))
	}

	if len(config) < 16 {
		return nil, &ErrorWithMessage{Err: ErrLargeBlobsIntegrityCheck, Message: "invalid large blobs response length"}
	}

	bLargeBlobs := config[:len(config)-16]
	hash := config[len(config)-16:]

	hasher := sha256.New()
	hasher.Write(bLargeBlobs)

	if !slices.Equal(hash, hasher.Sum(nil)[:16]) {
		return nil, &ErrorWithMessage{Err: ErrLargeBlobsIntegrityCheck, Message: "large blobs checksum mismatch"}
	}

	var blobs []protocol.LargeBlob
	if err := cbor.Unmarshal(bLargeBlobs, &blobs); err != nil {
		return nil, SyntaxError
	}

	return blobs, nil
}

// SetLargeBlobs stores large blobs on the device, ensuring compatibility with its supported capabilities and limits.
// It validates device support, fragments the blob data if needed, and sends it in chunks to the device.
// Returns an error if the device does not support large blobs, the data exceeds size limits, or if any other failure occurs.
//
// SetLargeBlobs replaces the device's entire large-blob array. Callers must serialize the complete read-modify-write
// operation across all writers that access the authenticator. Device serializes individual method calls, but separate
// GetLargeBlobs and SetLargeBlobs calls are not atomic; concurrent writers can overwrite each other's changes.
func (d *Device) SetLargeBlobs(ctx context.Context, pinUvAuthToken []byte, blobs []protocol.LargeBlob) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if err := d.ensureInfoLocked(ctx); err != nil {
		return err
	}

	return d.setLargeBlobsLocked(ctx, pinUvAuthToken, blobs)
}

func (d *Device) setLargeBlobsLocked(ctx context.Context, pinUvAuthToken []byte, blobs []protocol.LargeBlob) error {
	largeBlobs, ok := d.info.Options[protocol.OptionLargeBlobs]
	if !ok || !largeBlobs {
		return &ErrorWithMessage{Err: ErrNotSupported, Message: "device doesn't support largeBlobs"}
	}

	set, err := marshalLargeBlobArray(blobs)
	if err != nil {
		return err
	}

	pinUvAuthProtocol, err := d.pinUvAuthProtocolForRequest(
		pinUvAuthToken,
		largeBlobsAuthorizationRequired(d.info),
	)
	if err != nil {
		return err
	}

	hasher := sha256.New()
	hasher.Write(set)
	hash := hasher.Sum(nil)

	set = slices.Concat(set, hash[:16])

	maxSerializedLargeBlobArray, ok := d.info.MaxSerializedLargeBlobArrayValue()
	if !ok {
		return &ErrorWithMessage{Err: ErrNotSupported, Message: "device reports largeBlobs without maxSerializedLargeBlobArray"}
	}

	if uint(len(set)) > maxSerializedLargeBlobArray {
		return &ErrorWithMessage{Err: ErrLargeBlobsTooBig, Message: fmt.Sprintf(
			"this device max serialized large blob size is %db while you are trying to save %db",
			maxSerializedLargeBlobArray,
			len(set),
		)}
	}

	maxFragmentLength := d.maxFragmentLength()
	offset := uint(0)
	length := uint(len(set))

	for chunk := range slices.Chunk(set, int(maxFragmentLength)) {
		if offset > 0 {
			length = 0
		}

		if _, err := d.ctapClient.LargeBlobs(
			ctx,
			pinUvAuthProtocol,
			pinUvAuthToken,
			0,
			chunk,
			offset,
			length,
		); err != nil {
			return err
		}

		offset += uint(len(chunk))
	}

	return nil
}

// EnableEnterpriseAttestation enables enterprise attestation on the device if supported, using the provided token.
func (d *Device) EnableEnterpriseAttestation(ctx context.Context, pinUvAuthToken []byte) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if err := d.ensureInfoLocked(ctx); err != nil {
		return err
	}

	const subCommand = protocol.ConfigSubCommandEnableEnterpriseAttestation
	if err := validateAuthenticatorConfigCommand(d.info, subCommand); err != nil {
		return err
	}

	if _, ok := d.info.Options[protocol.OptionEnterpriseAttestation]; !ok {
		return &ErrorWithMessage{Err: ErrNotSupported, Message: "device doesn't support ep"}
	}

	pinUvAuthProtocol, err := d.pinUvAuthProtocolForRequest(
		pinUvAuthToken,
		configAuthorizationRequired(d.info, subCommand),
	)
	if err != nil {
		return err
	}

	if err := d.ctapClient.EnableEnterpriseAttestation(
		ctx,
		pinUvAuthProtocol,
		pinUvAuthToken,
	); err != nil {
		return err
	}

	d.invalidateInfoLocked()

	return nil
}

// ToggleAlwaysUV toggles the always UV (User Verification) setting on the device if supported, using the provided token.
func (d *Device) ToggleAlwaysUV(ctx context.Context, pinUvAuthToken []byte) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if err := d.ensureInfoLocked(ctx); err != nil {
		return err
	}

	const subCommand = protocol.ConfigSubCommandToggleAlwaysUv
	if err := validateAuthenticatorConfigCommand(d.info, subCommand); err != nil {
		return err
	}

	if _, ok := d.info.Options[protocol.OptionAlwaysUv]; !ok {
		return &ErrorWithMessage{Err: ErrNotSupported, Message: "device doesn't support alwaysUv"}
	}

	pinUvAuthProtocol, err := d.pinUvAuthProtocolForRequest(
		pinUvAuthToken,
		configAuthorizationRequired(d.info, subCommand),
	)
	if err != nil {
		return err
	}

	if err := d.ctapClient.ToggleAlwaysUV(
		ctx,
		pinUvAuthProtocol,
		pinUvAuthToken,
	); err != nil {
		return err
	}

	d.invalidateInfoLocked()

	return nil
}

// SetMinPINLength configures any subset of the PIN policy parameters accepted
// by the setMinPINLength authenticatorConfig subcommand.
func (d *Device) SetMinPINLength(
	ctx context.Context,
	pinUvAuthToken []byte,
	params protocol.SetMinPINLengthConfigSubCommandParams,
) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if err := d.ensureInfoLocked(ctx); err != nil {
		return err
	}

	const subCommand = protocol.ConfigSubCommandSetMinPINLength
	if err := validateAuthenticatorConfigCommand(d.info, subCommand); err != nil {
		return err
	}

	if !d.info.Options[protocol.OptionSetMinPINLength] {
		return &ErrorWithMessage{Err: ErrNotSupported, Message: "device doesn't support setMinPINLength"}
	}

	if err := validateSetMinPINLength(d.info, params); err != nil {
		return err
	}

	pinUvAuthProtocol, err := d.pinUvAuthProtocolForRequest(
		pinUvAuthToken,
		configAuthorizationRequired(d.info, subCommand),
	)
	if err != nil {
		return err
	}

	if err := d.ctapClient.SetMinPINLength(
		ctx,
		pinUvAuthProtocol,
		pinUvAuthToken,
		params,
	); err != nil {
		return d.pinPolicyError(err)
	}

	d.invalidateInfoLocked()

	return nil
}

// EnableLongTouchForReset enables the requirement for a long touch before the
// authenticator accepts a reset command.
func (d *Device) EnableLongTouchForReset(ctx context.Context, pinUvAuthToken []byte) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if err := d.ensureInfoLocked(ctx); err != nil {
		return err
	}

	const subCommand = protocol.ConfigSubCommandEnableLongTouchForReset
	if err := validateAuthenticatorConfigCommand(d.info, subCommand); err != nil {
		return err
	}

	if d.info.LongTouchForReset == nil {
		return &ErrorWithMessage{Err: ErrNotSupported, Message: "device doesn't support longTouchForReset"}
	}

	pinUvAuthProtocol, err := d.pinUvAuthProtocolForRequest(
		pinUvAuthToken,
		configAuthorizationRequired(d.info, subCommand),
	)
	if err != nil {
		return err
	}

	if err := d.ctapClient.EnableLongTouchForReset(
		ctx,
		pinUvAuthProtocol,
		pinUvAuthToken,
	); err != nil {
		return err
	}

	d.invalidateInfoLocked()

	return nil
}
