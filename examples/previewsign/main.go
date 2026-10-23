package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"os"
	"slices"

	"github.com/fxamacker/cbor/v2"
	"github.com/telesma-app/ctap/arkg"
	"github.com/telesma-app/ctap/authenticator"
	directhid "github.com/telesma-app/ctap/backend/hid"
	"github.com/telesma-app/ctap/cose"
	"github.com/telesma-app/ctap/credential"
	"github.com/telesma-app/ctap/extension"
	"github.com/telesma-app/ctap/protocol"
	"github.com/telesma-app/ctap/webauthn"
)

const rpID = "preview-sign.example"

var message = []byte("hello from previewSign")

func main() {
	if err := run(context.Background()); err != nil {
		log.Fatal(err)
	}
}

func run(ctx context.Context) error {
	pin := os.Getenv("FIDO2_PIN")

	device, err := authenticator.Select(ctx, directhid.Enumerate)
	if err != nil {
		return err
	}
	defer device.Close()

	info, _ := device.GetInfoCached()
	if !slices.Contains(info.Extensions, extension.ExtensionIdentifierPreviewSign) {
		return errors.New("authenticator does not support previewSign")
	}

	var makeCredentialToken []byte
	if pin != "" {
		makeCredentialToken, err = device.GetPinUvAuthTokenUsingPIN(
			ctx,
			pin,
			protocol.PermissionMakeCredential,
			rpID,
		)
		if err != nil {
			return err
		}
	}

	fmt.Println("Touch the authenticator to create a credential and signing key.")
	registration, err := device.MakeCredential(
		ctx,
		makeCredentialToken,
		[]byte(`{"type":"webauthn.create","challenge":"previewSign example"}`),
		credential.PublicKeyCredentialRpEntity{ID: rpID, Name: "previewSign example"},
		credential.PublicKeyCredentialUserEntity{
			ID:          []byte("preview-sign-user"),
			Name:        "preview-sign-user",
			DisplayName: "previewSign user",
		},
		[]credential.PublicKeyCredentialParameters{{
			Type:      credential.PublicKeyCredentialTypePublicKey,
			Algorithm: cose.AlgorithmES256,
		}},
		nil,
		&webauthn.CreateAuthenticationExtensionsClientInputs{
			PreviewSignInputs: &webauthn.PreviewSignInputs{
				PreviewSign: webauthn.AuthenticationExtensionsPreviewSignInputs{
					GenerateKey: &webauthn.PreviewSignGenerateKeyInputs{
						Algorithms: []cose.Algorithm{cose.AlgorithmESP256SplitARKGPlaceholder},
					},
				},
			},
		},
		nil,
		0,
		nil,
	)
	clear(makeCredentialToken)
	if err != nil {
		return err
	}
	credentialID := registration.AuthData.AttestedCredentialData.CredentialID
	generatedKey := registration.ExtensionOutputs.PreviewSign.GeneratedKey
	fmt.Printf("Credential ID: %s\n", base64.RawURLEncoding.EncodeToString(credentialID))
	fmt.Printf("Signing key handle: %s\n", base64.RawURLEncoding.EncodeToString(generatedKey.KeyHandle))
	fmt.Printf("Signing algorithm: %d\n", generatedKey.Algorithm)
	fmt.Printf("Signing public seed (COSE): %x\n", generatedKey.PublicKey)
	fmt.Printf("Signing key attestation: %d bytes\n", len(generatedKey.AttestationObject))

	var publicSeed cose.Key
	if err := cbor.Unmarshal(generatedKey.PublicKey, &publicSeed); err != nil {
		return fmt.Errorf("decode signing public seed: %w", err)
	}
	inputKeyMaterial := make([]byte, 32)
	if _, err := rand.Read(inputKeyMaterial); err != nil {
		return fmt.Errorf("generate ARKG input key material: %w", err)
	}
	defer clear(inputKeyMaterial)
	arkgContext := []byte(rpID)
	verificationKey, arkgKeyHandle, err := arkg.DeriveP256(publicSeed, inputKeyMaterial, arkgContext)
	if err != nil {
		return fmt.Errorf("derive ARKG-P256 signing key: %w", err)
	}
	encMode, err := cbor.CTAP2EncOptions().EncMode()
	if err != nil {
		return fmt.Errorf("create CTAP2 CBOR encoder: %w", err)
	}
	additionalArguments, err := encMode.Marshal(map[int]any{
		3:  generatedKey.Algorithm,
		-1: arkgKeyHandle,
		-2: arkgContext,
	})
	if err != nil {
		return fmt.Errorf("encode COSE signing arguments: %w", err)
	}
	encodedVerificationKey, err := encMode.Marshal(verificationKey)
	if err != nil {
		return fmt.Errorf("encode derived signing public key: %w", err)
	}
	fmt.Printf("Derived signing public key (COSE): %x\n", encodedVerificationKey)

	credentialDescriptor := credential.PublicKeyCredentialDescriptor{
		Type: credential.PublicKeyCredentialTypePublicKey,
		ID:   credentialID,
	}
	encodedCredentialID := base64.RawURLEncoding.EncodeToString(credentialID)
	messageDigest := sha256.Sum256(message)
	var getAssertionToken []byte
	if pin != "" {
		getAssertionToken, err = device.GetPinUvAuthTokenUsingPIN(
			ctx,
			pin,
			protocol.PermissionGetAssertion,
			rpID,
		)
		if err != nil {
			return err
		}
	}
	defer clear(getAssertionToken)
	fmt.Println("Touch the authenticator to sign the message.")

	var assertionSignature []byte
	for assertion, err := range device.GetAssertion(
		ctx,
		getAssertionToken,
		rpID,
		[]byte(`{"type":"webauthn.get","challenge":"previewSign example"}`),
		[]credential.PublicKeyCredentialDescriptor{credentialDescriptor},
		&webauthn.GetAuthenticationExtensionsClientInputs{
			PreviewSignInputs: &webauthn.PreviewSignInputs{
				PreviewSign: webauthn.AuthenticationExtensionsPreviewSignInputs{
					SignByCredential: map[string]webauthn.PreviewSignSignInputs{
						encodedCredentialID: {
							KeyHandle:           generatedKey.KeyHandle,
							ToBeSigned:          messageDigest[:],
							AdditionalArguments: additionalArguments,
						},
					},
				},
			},
		},
		nil,
	) {
		if err != nil {
			return err
		}
		assertionSignature = assertion.ExtensionOutputs.PreviewSign.Signature
	}
	if len(assertionSignature) == 0 {
		return errors.New("authenticator returned an empty previewSign signature")
	}

	verificationAlgorithm, err := verificationKey.Algorithm()
	if err != nil {
		return err
	}
	publicKey, err := verificationKey.PublicKey()
	if err != nil {
		return err
	}
	if err := cose.VerifySignature(publicKey, verificationAlgorithm, message, assertionSignature); err != nil {
		return fmt.Errorf("verify previewSign signature: %w", err)
	}

	fmt.Printf("Message: %q\n", message)
	fmt.Printf("Signature: %x\n", assertionSignature)
	fmt.Printf("Verification algorithm: %d\n", verificationAlgorithm)
	fmt.Println("Signature verified.")
	return nil
}
