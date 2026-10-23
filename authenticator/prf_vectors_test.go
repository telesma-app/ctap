package authenticator

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"testing"

	"github.com/telesma-app/ctap/crypto/protocolone"
	"github.com/telesma-app/ctap/crypto/protocoltwo"
	"github.com/telesma-app/ctap/webauthn"
)

// These values are published in WebAuthn Level 3, § 16.17.1:
// https://www.w3.org/TR/2026/CR-webauthn-3-20260526/#sctn-prf-extension-test-vectors
func TestWebAuthnPRFReferenceVectors(t *testing.T) {
	platformPrivateKey := decodePRFVector(t, "0971bc7fb1be48270adcd3d9a5fc15d5fb0f335b3071ff36a54c007fa6c76514")
	authenticatorPublicKeyX := decodePRFVector(t, "a30522c2de402b561965c3cf949a1cab020c6f6ea36fcf7e911ac1a0f1515300")
	authenticatorPublicKeyY := decodePRFVector(t, "9961a929abdb2f42e6566771887d41484d889e735e3248518a53112d2b915f00")
	credentialRandom := decodePRFVector(t, "437e065e723a98b2f08f39d8baf7c53ecb3c363c5e5104bdaaf5d5ca2e028154")

	firstInput := decodePRFVector(t, "576562417574686e20505246207465737420766563746f727302")
	secondInput := decodePRFVector(t, "576562417574686e20505246207465737420766563746f727303")
	firstSalt := decodePRFVector(t, "527413ebb48293772df30f031c5ac4650c7de14bf9498671ae163447b6a772b3")
	secondSalt := decodePRFVector(t, "d68ac03329a10ee5e0ec834492bb9a96a0e547baf563bf78ccbe8789b22e776b")
	firstOutput := decodePRFVector(t, "3c33e07d202c3b029cc21f1722767021bf27d595933b3d2b6a1b9d5dddc77fae")
	secondOutput := decodePRFVector(t, "a62a8773b19cda90d7ed4ef72a80a804320dbd3997e2f663805ad1fd3293d50b")

	salts := prfSalts(webauthn.AuthenticationExtensionsPRFValues{
		First:  firstInput,
		Second: secondInput,
	})
	if got, want := salts, slices.Concat(firstSalt, secondSalt); (got == nil) != (want == nil) || !bytes.Equal(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}

	if got, want := hmacSHA256(credentialRandom, firstSalt), firstOutput; (got == nil) != (want == nil) || !bytes.Equal(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}

	if got, want := hmacSHA256(credentialRandom, secondSalt), secondOutput; (got == nil) != (want == nil) || !bytes.Equal(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}

	curve := ecdh.P256()

	privateKey, err := curve.NewPrivateKey(platformPrivateKey)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	publicKey, err := curve.NewPublicKey(slices.Concat(
		[]byte{0x04},
		authenticatorPublicKeyX,
		authenticatorPublicKeyY,
	))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ecdhSecret, err := privateKey.ECDH(publicKey)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	t.Run("PIN UV protocol one", func(t *testing.T) {
		sharedSecret := protocolone.KDF(ecdhSecret)
		if got, want := sharedSecret, decodePRFVector(t, "23e5ed7157c25892b77732fb9c8a107e3518800db2af4142f9f4adfacb771d39"); (got == nil) != (want == nil) || !bytes.Equal(got, want) {
			t.Errorf("got %#v, want %#v", got, want)
		}

		saltEnc := decodePRFVector(t, "ab8c878bb05d04700f077ed91845ec9c503c925cb12b327ddbeb4243c397f913")
		outputEnc := decodePRFVector(t, "15d4e4f3f04109b492b575c1b38c28585b6719cf8d61304215108d939f37ccfb")
		assertPRFVectorDecryption(t, protocolone.Decrypt, sharedSecret, saltEnc, firstSalt)
		assertPRFVectorDecryption(t, protocolone.Decrypt, sharedSecret, outputEnc, firstOutput)

		gotSaltEnc, err := protocolone.Encrypt(sharedSecret, firstSalt)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if got, want := gotSaltEnc, saltEnc; (got == nil) != (want == nil) || !bytes.Equal(got, want) {
			t.Errorf("got %#v, want %#v", got, want)
		}
	})

	t.Run("PIN UV protocol two", func(t *testing.T) {
		sharedSecret, err := protocoltwo.KDF(ecdhSecret)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if got, want := sharedSecret, decodePRFVector(t, "0c63083de8170101d38bcf8bd72309568ddb4550867e23404b35d85712f7c20d8bc911ee23c06034cbc14290b9669bec07739053c5a416e313ef905c79955876"); (got == nil) != (want == nil) || !bytes.Equal(got, want) {
			t.Errorf("got %#v, want %#v", got, want)
		}

		assertPRFVectorDecryption(
			t,
			protocoltwo.Decrypt,
			sharedSecret,
			decodePRFVector(t, "23dde5e3462daf36559b85c4ac5f9656aa9bfd81c1dc2bf8533c8b9f3882854786b4f500e25b4e3d81f7fc7c74236229"),
			firstSalt,
		)
		assertPRFVectorDecryption(
			t,
			protocoltwo.Decrypt,
			sharedSecret,
			decodePRFVector(t, "3bfaa48f7952330d63e35ff8cd5bca48d2a12823828915749287256ab146272f9fb437bf65691243c3f504bd7ea6d5e6"),
			firstOutput,
		)
		assertPRFVectorDecryption(
			t,
			protocoltwo.Decrypt,
			sharedSecret,
			decodePRFVector(t, "d9f4236403e0fe843a8e4e5be764d120904c198ad6e77b089876a3391961f183b0008b4ca66b91cd72aa35b6151ff981f6e5649f3c040e6615ad7dd8ae96ef23b229a5c97c3f0dcd8605eee166ce163a"),
			slices.Concat(firstSalt, secondSalt),
		)
		assertPRFVectorDecryption(
			t,
			protocoltwo.Decrypt,
			sharedSecret,
			decodePRFVector(t, "90ee52f739043bc17b3488a74306d7801debb5b61f18662c648a25b5b5678ede482cdaff99a537a44f064fcb10ce6e04dfd27619dc96a0daff8507e499296b1eecf0981f7c8518b277a7a3018f5ec6fb"),
			slices.Concat(firstOutput, secondOutput),
		)
	})
}

func decodePRFVector(t *testing.T, value string) []byte {
	t.Helper()

	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	return decoded
}

func hmacSHA256(key, input []byte) []byte {
	hasher := hmac.New(sha256.New, key)
	hasher.Write(input)

	return hasher.Sum(nil)
}

func assertPRFVectorDecryption(
	t *testing.T,
	decrypt func([]byte, []byte) ([]byte, error),
	sharedSecret []byte,
	ciphertext []byte,
	want []byte,
) {
	t.Helper()

	got, err := decrypt(sharedSecret, ciphertext)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got, want := got, want; (got == nil) != (want == nil) || !bytes.Equal(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}
