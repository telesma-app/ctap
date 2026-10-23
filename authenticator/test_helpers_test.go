package authenticator

import (
	"context"
	"crypto/ecdh"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/binary"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/telesma-app/ctap/client"
	"github.com/telesma-app/ctap/cose"
	"github.com/telesma-app/ctap/internal/testhid"
	"github.com/telesma-app/ctap/options"
	"github.com/telesma-app/ctap/protocol"
	"github.com/telesma-app/ctap/transport/ctaphid"
)

var testCID = ctaphid.ChannelID{1, 2, 3, 4}
var testContext = context.Background()

func newTestDevice(t testing.TB, fake *testhid.Device, info protocol.AuthenticatorGetInfoResponse) *Device {
	t.Helper()

	transport := testhid.Transport{Device: fake, CID: testCID}

	ctapClient, err := client.NewClient(options.WithTransport(transport))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	return &Device{
		transport:  transport,
		ctapClient: ctapClient,
		info:       info,
		infoValid:  true,
	}
}

func encodeCBOR(t testing.TB, v any) []byte {
	t.Helper()

	b, err := cbor.Marshal(v)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	return b
}

func testKeyAgreement(t testing.TB) cose.Key {
	t.Helper()

	privateKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	coseKey, err := cose.KeyFromP256PublicKey(privateKey.PublicKey())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	return coseKey
}

func minimalAuthData() []byte {
	return make([]byte, 37)
}

func minimalMakeCredentialAuthData(t testing.TB) []byte {
	t.Helper()
	return makeCredentialAuthData(t, testP256CredentialKey(cose.AlgorithmES256))
}

func makeCredentialAuthData(t testing.TB, key cose.Key) []byte {
	t.Helper()

	data := make([]byte, 37)
	data[32] = byte(protocol.AuthDataFlagAttestedCredentialDataIncluded)
	data = append(data, make([]byte, 16)...)
	credentialID := []byte("credential-id")
	length := make([]byte, 2)
	binary.BigEndian.PutUint16(length, uint16(len(credentialID)))
	data = append(data, length...)
	data = append(data, credentialID...)
	data = append(data, encodeCBOR(t, key)...)

	return data
}

func testP256CredentialKey(algorithm cose.Algorithm) cose.Key {
	curve := elliptic.P256().Params()

	return cose.Key{
		cose.KeyParameterKty:    cose.KeyTypeEC2,
		cose.KeyParameterAlg:    algorithm,
		cose.EC2KeyParameterCrv: cose.EllipticCurveP256,
		cose.EC2KeyParameterX:   curve.Gx.FillBytes(make([]byte, 32)),
		cose.EC2KeyParameterY:   curve.Gy.FillBytes(make([]byte, 32)),
	}
}

func hmacSecretIsZero(secret protocol.HMACSecret) bool {
	return secret.KeyAgreement == nil &&
		secret.SaltEnc == nil &&
		secret.SaltAuth == nil &&
		secret.PinUvAuthProtocol == 0
}

func assertionResponseIsZero(response protocol.AuthenticatorGetAssertionResponse) bool {
	return response.Credential.Type == "" &&
		response.Credential.ID == nil &&
		response.Credential.Transports == nil &&
		response.AuthDataRaw == nil &&
		response.AuthData == nil &&
		response.Signature == nil &&
		response.User == nil &&
		response.NumberOfCredentials == 0 &&
		!response.UserSelected &&
		response.LargeBlobKey == nil &&
		response.UnsignedExtensionOutputs == nil &&
		response.ExtensionOutputs == nil
}

func credentialManagementResponseIsZero(response protocol.AuthenticatorCredentialManagementResponse) bool {
	return response.ExistingResidentCredentialsCount == nil &&
		response.MaxPossibleRemainingResidentCredentialsCount == nil &&
		response.RP.ID == "" &&
		response.RP.Name == "" &&
		response.RPIDHash == nil &&
		response.TotalRPs == 0 &&
		response.User.ID == nil &&
		response.User.DisplayName == "" &&
		response.User.Name == "" &&
		response.User.Icon == "" &&
		response.CredentialID.Type == "" &&
		response.CredentialID.ID == nil &&
		response.CredentialID.Transports == nil &&
		response.PublicKey == nil &&
		response.TotalCredentials == 0 &&
		response.CredProtect == 0 &&
		response.LargeBlobKey == nil &&
		response.ThirdPartyPayment == nil
}

func assertNoAuthenticatorIO(t testing.TB, fake *testhid.Device) {
	t.Helper()

	if got := fake.Writes(); len(got) != 0 {
		t.Errorf("got non-empty value %#v; context: %s", got, "validation must fail before transport I/O")
	}
}
