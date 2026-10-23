package authenticator

import (
	"errors"
	"maps"
	"testing"

	"github.com/telesma-app/ctap/extension"
	"github.com/telesma-app/ctap/internal/testhid"
	"github.com/telesma-app/ctap/protocol"
	"github.com/telesma-app/ctap/webauthn"
)

func TestBioEnrollmentMode(t *testing.T) {
	tests := []struct {
		name        string
		info        protocol.AuthenticatorGetInfoResponse
		wantCommand protocol.Command
	}{
		{
			name: "FIDO 2.1",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_0, protocol.FIDO_2_1},
				Options: map[protocol.Option]bool{
					protocol.OptionBioEnroll: false,
				},
			},
			wantCommand: protocol.AuthenticatorBioEnrollment,
		},
		{
			name: "FIDO 2.1 preview with enrollment",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_0, protocol.FIDO_2_1_PRE},
				Options: map[protocol.Option]bool{
					protocol.OptionUserVerificationMgmtPreview: true,
				},
			},
			wantCommand: protocol.PrototypeAuthenticatorBioEnrollment,
		},
		{
			name: "FIDO 2.1 preview without enrollment",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_0, protocol.FIDO_2_1_PRE},
				Options: map[protocol.Option]bool{
					protocol.OptionUserVerificationMgmtPreview: false,
				},
			},
			wantCommand: protocol.PrototypeAuthenticatorBioEnrollment,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := testhid.NewCBORDevice(t, testCID, encodeCBOR(t, protocol.AuthenticatorBioEnrollmentResponse{}))
			d := newTestDevice(t, fake, tt.info)

			_, err := d.GetBioModality(testContext)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			command, _ := fake.FirstCTAPPayload(t)
			if got, want := command, tt.wantCommand; got != want {
				t.Errorf("got %#v, want %#v", got, want)
			}
		})
	}
}

func TestBioEnrollmentPreviewAbsentIsNotSupported(t *testing.T) {
	fake := testhid.NewCBORDevice(t, testCID)
	d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
		Versions: protocol.Versions{protocol.FIDO_2_0, protocol.FIDO_2_1_PRE},
		Options:  map[protocol.Option]bool{},
	})

	_, err := d.GetBioModality(testContext)
	if err, target := err, ErrNotSupported; !errors.Is(err, target) {
		t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
	}

	assertNoAuthenticatorIO(t, fake)
}

func TestProtectedSubcommandsRejectMissingOrMalformedTokenBeforeCommand(t *testing.T) {
	t.Run("BioEnrollment requires token", func(t *testing.T) {
		fake := testhid.NewCBORDevice(t, testCID)
		d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
			PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolTwo},
			Options: map[protocol.Option]bool{
				protocol.OptionBioEnroll: false,
			},
		})

		_, err := d.EnrollBegin(testContext, nil, 0)
		if err, target := err, ErrPinUvAuthTokenRequired; !errors.Is(err, target) {
			t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
		}

		assertNoAuthenticatorIO(t, fake)
	})

	t.Run("CredentialManagement requires token", func(t *testing.T) {
		fake := testhid.NewCBORDevice(t, testCID)
		d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
			PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolTwo},
			Options: map[protocol.Option]bool{
				protocol.OptionCredentialManagement: true,
			},
		})

		_, err := d.GetCredsMetadata(testContext, nil)
		if err, target := err, ErrPinUvAuthTokenRequired; !errors.Is(err, target) {
			t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
		}

		assertNoAuthenticatorIO(t, fake)
	})

	t.Run("protocol 2 rejects short token without panic", func(t *testing.T) {
		fake := testhid.NewCBORDevice(t, testCID)
		d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
			PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolTwo},
			Options: map[protocol.Option]bool{
				protocol.OptionCredentialManagement: true,
			},
		})

		_, err := d.GetCredsMetadata(testContext, make([]byte, 16))
		if err, target := err, SyntaxError; !errors.Is(err, target) {
			t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
		}

		assertNoAuthenticatorIO(t, fake)
	})
}

func TestPinUvAuthTokenLengthUsesCTAPVersion(t *testing.T) {
	skipAuthenticatorFIPS140(t)

	t.Run("FIDO 2.0 accepts a longer protocol 1 token", func(t *testing.T) {
		d := newTestDevice(t, testhid.NewCBORDevice(t, testCID), protocol.AuthenticatorGetInfoResponse{
			Versions:           protocol.Versions{protocol.FIDO_2_0},
			PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolOne},
		})

		got, err := d.pinUvAuthProtocolForRequest(make([]byte, 48), true)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if got, want := got, protocol.PinUvAuthProtocolOne; got != want {
			t.Errorf("got %#v, want %#v", got, want)
		}
	})

	t.Run("FIDO 2.1 rejects a longer protocol 1 token", func(t *testing.T) {
		d := newTestDevice(t, testhid.NewCBORDevice(t, testCID), protocol.AuthenticatorGetInfoResponse{
			Versions:           protocol.Versions{protocol.FIDO_2_1},
			PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolOne},
		})

		_, err := d.pinUvAuthProtocolForRequest(make([]byte, 48), true)
		if err, target := err, SyntaxError; !errors.Is(err, target) {
			t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
		}
	})

	t.Run("FIDO 2.1 Preview accepts a longer protocol 1 token", func(t *testing.T) {
		d := newTestDevice(t, testhid.NewCBORDevice(t, testCID), protocol.AuthenticatorGetInfoResponse{
			Versions:           protocol.Versions{protocol.FIDO_2_0, protocol.FIDO_2_1_PRE},
			PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolOne},
		})

		got, err := d.pinUvAuthProtocolForRequest(make([]byte, 48), true)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if got, want := got, protocol.PinUvAuthProtocolOne; got != want {
			t.Errorf("got %#v, want %#v", got, want)
		}
	})
}

func TestSelectPinTokenFlowUsingPIN(t *testing.T) {
	baseOptions := map[protocol.Option]bool{
		protocol.OptionClientPIN:      true,
		protocol.OptionPinUvAuthToken: true,
	}

	tests := []struct {
		name       string
		info       protocol.AuthenticatorGetInfoResponse
		permission protocol.Permission
		rpID       string
		wantFlow   pinTokenFlow
		wantErr    error
	}{
		{
			name: "permissioned mc requires RP ID",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_1},
				Options:  baseOptions,
			},
			permission: protocol.PermissionMakeCredential,
			wantErr:    SyntaxError,
		},
		{
			name: "legacy mc binds RP on first use",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_0},
				Options: map[protocol.Option]bool{
					protocol.OptionClientPIN: true,
				},
			},
			permission: protocol.PermissionMakeCredential,
			wantFlow:   pinTokenFlowLegacy,
		},
		{
			name: "FIDO 2.0 legacy token allows zero permission",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_0},
				Options: map[protocol.Option]bool{
					protocol.OptionClientPIN: true,
				},
			},
			permission: protocol.PermissionNone,
			wantFlow:   pinTokenFlowLegacy,
		},
		{
			name: "FIDO 2.0 ignores unknown pinUvAuthToken option",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_0},
				Options: map[protocol.Option]bool{
					protocol.OptionClientPIN:      true,
					protocol.OptionPinUvAuthToken: true,
				},
			},
			permission: protocol.PermissionMakeCredential,
			wantFlow:   pinTokenFlowLegacy,
		},
		{
			name: "standard bio false still grants be",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_1},
				Options: map[protocol.Option]bool{
					protocol.OptionClientPIN:      true,
					protocol.OptionPinUvAuthToken: true,
					protocol.OptionBioEnroll:      false,
				},
			},
			permission: protocol.PermissionBioEnrollment,
			wantFlow:   pinTokenFlowWithPermissions,
		},
		{
			name: "preview bio without enrollment uses legacy token",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_0, protocol.FIDO_2_1_PRE},
				Options: map[protocol.Option]bool{
					protocol.OptionClientPIN:                   true,
					protocol.OptionPinUvAuthToken:              true,
					protocol.OptionUserVerificationMgmtPreview: false,
				},
			},
			permission: protocol.PermissionBioEnrollment,
			wantFlow:   pinTokenFlowLegacy,
		},
		{
			name: "legacy token cannot grant standard cm",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_1},
				Options: map[protocol.Option]bool{
					protocol.OptionClientPIN:            true,
					protocol.OptionCredentialManagement: true,
				},
			},
			permission: protocol.PermissionCredentialManagement,
			wantErr:    ErrNotSupported,
		},
		{
			name: "pcmr cannot be combined",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_3},
				Options:  baseOptions,
			},
			permission: protocol.PermissionPersistentCredentialManagementReadOnly |
				protocol.PermissionCredentialManagement,
			wantErr: SyntaxError,
		},
		{
			name: "zero permission",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_1},
				Options:  baseOptions,
			},
			permission: protocol.PermissionNone,
			wantErr:    SyntaxError,
		},
		{
			name: "FIDO 2.1 rejects zero permission even with legacy token flow",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_1},
				Options: map[protocol.Option]bool{
					protocol.OptionClientPIN: true,
				},
			},
			permission: protocol.PermissionNone,
			wantErr:    SyntaxError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flow, err := selectPinTokenFlowUsingPIN(tt.info, tt.permission, tt.rpID)
			if tt.wantErr != nil {
				if err, target := err, tt.wantErr; !errors.Is(err, target) {
					t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
				}

				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if got, want := flow, tt.wantFlow; got != want {
				t.Errorf("got %#v, want %#v", got, want)
			}
		})
	}
}

func TestSelectPinUvAuthTokenFlowUsingUV(t *testing.T) {
	baseInfo := protocol.AuthenticatorGetInfoResponse{
		Versions: protocol.Versions{protocol.FIDO_2_3},
		Options: map[protocol.Option]bool{
			protocol.OptionPinUvAuthToken:   true,
			protocol.OptionUserVerification: true,
		},
	}

	t.Run("be requires uvBioEnroll", func(t *testing.T) {
		info := baseInfo
		info.Options = map[protocol.Option]bool{
			protocol.OptionPinUvAuthToken:   true,
			protocol.OptionUserVerification: true,
			protocol.OptionBioEnroll:        false,
		}

		_, err := selectPinUvAuthTokenFlowUsingUV(info, protocol.PermissionBioEnrollment, "")
		if err, target := err, ErrNotSupported; !errors.Is(err, target) {
			t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
		}

		info.Options[protocol.OptionUvBioEnroll] = true

		flow, err := selectPinUvAuthTokenFlowUsingUV(info, protocol.PermissionBioEnrollment, "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if got, want := flow, uvTokenFlowWithPermissions; got != want {
			t.Errorf("got %#v, want %#v", got, want)
		}
	})

	t.Run("acfg requires uvAcfg and authnrCfg", func(t *testing.T) {
		info := baseInfo
		info.Options = map[protocol.Option]bool{
			protocol.OptionPinUvAuthToken:   true,
			protocol.OptionUserVerification: true,
			protocol.OptionUvAcfg:           true,
		}

		_, err := selectPinUvAuthTokenFlowUsingUV(info, protocol.PermissionAuthenticatorConfiguration, "")
		if err, target := err, ErrNotSupported; !errors.Is(err, target) {
			t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
		}

		info.Options[protocol.OptionAuthenticatorConfig] = true

		flow, err := selectPinUvAuthTokenFlowUsingUV(info, protocol.PermissionAuthenticatorConfiguration, "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if got, want := flow, uvTokenFlowWithPermissions; got != want {
			t.Errorf("got %#v, want %#v", got, want)
		}
	})

	t.Run("ga requires RP ID", func(t *testing.T) {
		_, err := selectPinUvAuthTokenFlowUsingUV(baseInfo, protocol.PermissionGetAssertion, "")
		if err, target := err, SyntaxError; !errors.Is(err, target) {
			t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
		}

		flow, err := selectPinUvAuthTokenFlowUsingUV(baseInfo, protocol.PermissionGetAssertion, "example.com")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if got, want := flow, uvTokenFlowWithPermissions; got != want {
			t.Errorf("got %#v, want %#v", got, want)
		}
	})

	t.Run("FIDO 2.0 ignores unknown pinUvAuthToken option", func(t *testing.T) {
		info := baseInfo
		info.Versions = protocol.Versions{protocol.FIDO_2_0}

		_, err := selectPinUvAuthTokenFlowUsingUV(info, protocol.PermissionGetAssertion, "example.com")
		if err, target := err, ErrNotSupported; !errors.Is(err, target) {
			t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
		}
	})

	previewInfo := protocol.AuthenticatorGetInfoResponse{
		Versions: protocol.Versions{protocol.FIDO_2_0, protocol.FIDO_2_1_PRE},
		PinUvAuthProtocols: []protocol.PinUvAuthProtocol{
			protocol.PinUvAuthProtocolOne,
		},
		Options: map[protocol.Option]bool{
			protocol.OptionUserVerification:            true,
			protocol.OptionUvToken:                     true,
			protocol.OptionCredentialManagementPreview: true,
			protocol.OptionUserVerificationMgmtPreview: false,
		},
	}

	t.Run("preview bio enrollment uses legacy UV token", func(t *testing.T) {
		flow, err := selectPinUvAuthTokenFlowUsingUV(
			previewInfo,
			protocol.PermissionBioEnrollment,
			"",
		)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if got, want := flow, uvTokenFlowPreview; got != want {
			t.Errorf("got %#v, want %#v", got, want)
		}
	})

	t.Run("preview credential management uses legacy UV token", func(t *testing.T) {
		flow, err := selectPinUvAuthTokenFlowUsingUV(
			previewInfo,
			protocol.PermissionCredentialManagement,
			"",
		)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if got, want := flow, uvTokenFlowPreview; got != want {
			t.Errorf("got %#v, want %#v", got, want)
		}
	})

	t.Run("preview get assertion does not require RP ID", func(t *testing.T) {
		flow, err := selectPinUvAuthTokenFlowUsingUV(
			previewInfo,
			protocol.PermissionGetAssertion,
			"",
		)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if got, want := flow, uvTokenFlowPreview; got != want {
			t.Errorf("got %#v, want %#v", got, want)
		}
	})

	t.Run("preview requires uvToken option", func(t *testing.T) {
		info := previewInfo
		info.Options = maps.Clone(previewInfo.Options)
		delete(info.Options, protocol.OptionUvToken)

		_, err := selectPinUvAuthTokenFlowUsingUV(info, protocol.PermissionBioEnrollment, "")
		if err, target := err, ErrNotSupported; !errors.Is(err, target) {
			t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
		}
	})

	t.Run("preview requires protocol one", func(t *testing.T) {
		info := previewInfo
		info.PinUvAuthProtocols = []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolTwo}

		_, err := selectPinUvAuthTokenFlowUsingUV(info, protocol.PermissionBioEnrollment, "")
		if err, target := err, ErrNotSupported; !errors.Is(err, target) {
			t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
		}
	})

	t.Run("preview allows omitted optional protocol list", func(t *testing.T) {
		info := previewInfo
		info.PinUvAuthProtocols = nil

		flow, err := selectPinUvAuthTokenFlowUsingUV(info, protocol.PermissionBioEnrollment, "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if got, want := flow, uvTokenFlowPreview; got != want {
			t.Errorf("got %#v, want %#v", got, want)
		}
	})

	t.Run("preview rejects permissions not granted by getUvToken", func(t *testing.T) {
		_, err := selectPinUvAuthTokenFlowUsingUV(previewInfo, protocol.PermissionLargeBlobWrite, "")
		if err, target := err, ErrNotSupported; !errors.Is(err, target) {
			t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
		}
	})
}

func TestConditionalAuthorizationUsesCTAPVersion(t *testing.T) {
	tests := []struct {
		name string
		info protocol.AuthenticatorGetInfoResponse
		want bool
	}{
		{
			name: "FIDO 2.0 ignores unknown alwaysUv",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_0},
				Options: map[protocol.Option]bool{
					protocol.OptionAlwaysUv: true,
				},
			},
		},
		{
			name: "FIDO 2.1 honors alwaysUv",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_0, protocol.FIDO_2_1},
				Options: map[protocol.Option]bool{
					protocol.OptionAlwaysUv: true,
				},
			},
			want: true,
		},
		{
			name: "FIDO 2.3 honors alwaysUv",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_3},
				Options: map[protocol.Option]bool{
					protocol.OptionAlwaysUv: true,
				},
			},
			want: true,
		},
		{
			name: "configured PIN protects every version",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_0},
				Options: map[protocol.Option]bool{
					protocol.OptionClientPIN: true,
				},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, want := largeBlobsAuthorizationRequired(tt.info), tt.want; got != want {
				t.Errorf("got %#v, want %#v", got, want)
			}
		})
	}
}

func TestSetLargeBlobsConditionalAuthorization(t *testing.T) {
	baseInfo := protocol.AuthenticatorGetInfoResponse{
		Versions:                    protocol.Versions{protocol.FIDO_2_1},
		MaxSerializedLargeBlobArray: 2048,
		Options: map[protocol.Option]bool{
			protocol.OptionLargeBlobs: true,
		},
	}

	t.Run("unprotected authenticator omits auth", func(t *testing.T) {
		fake := testhid.NewCBORDevice(t, testCID, nil)
		d := newTestDevice(t, fake, baseInfo)

		if err := d.SetLargeBlobs(testContext, nil, nil); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		command, request := fake.FirstCTAPRequestMap(t)
		if got, want := command, protocol.AuthenticatorLargeBlobs; got != want {
			t.Errorf("got %#v, want %#v", got, want)
		}

		if _, ok := request[uint64(5)]; ok {
			t.Errorf("value unexpectedly contains %#v", uint64(5))
		}

		if _, ok := request[uint64(6)]; ok {
			t.Errorf("value unexpectedly contains %#v", uint64(6))
		}
	})

	t.Run("protected authenticator requires auth", func(t *testing.T) {
		fake := testhid.NewCBORDevice(t, testCID)
		info := baseInfo
		info.Options = map[protocol.Option]bool{
			protocol.OptionLargeBlobs: true,
			protocol.OptionClientPIN:  true,
		}
		d := newTestDevice(t, fake, info)

		err := d.SetLargeBlobs(testContext, nil, nil)
		if err, target := err, ErrPinUvAuthTokenRequired; !errors.Is(err, target) {
			t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
		}

		assertNoAuthenticatorIO(t, fake)
	})
}

func TestAuthenticatorConfigCapabilityAndAuthorization(t *testing.T) {
	t.Run("unprotected SetMinPINLength omits auth", func(t *testing.T) {
		info := protocol.AuthenticatorGetInfoResponse{
			Versions: protocol.Versions{protocol.FIDO_2_3},
			Options: map[protocol.Option]bool{
				protocol.OptionAuthenticatorConfig: true,
				protocol.OptionSetMinPINLength:     true,
			},
			AuthenticatorConfigCommands: []protocol.ConfigSubCommand{protocol.ConfigSubCommandSetMinPINLength},
		}
		fake := testhid.NewCBORDevice(t, testCID, nil, encodeCBOR(t, info))
		d := newTestDevice(t, fake, info)

		if err := d.SetMinPINLength(testContext, nil, protocol.SetMinPINLengthConfigSubCommandParams{
			NewMinPINLength: new(uint(8)),
		}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		command, request := fake.FirstCTAPRequestMap(t)
		if got, want := command, protocol.AuthenticatorConfig; got != want {
			t.Errorf("got %#v, want %#v", got, want)
		}

		if _, ok := request[uint64(3)]; ok {
			t.Errorf("value unexpectedly contains %#v", uint64(3))
		}

		if _, ok := request[uint64(4)]; ok {
			t.Errorf("value unexpectedly contains %#v", uint64(4))
		}
	})

	t.Run("protected config requires auth", func(t *testing.T) {
		fake := testhid.NewCBORDevice(t, testCID)
		d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
			Versions: protocol.Versions{protocol.FIDO_2_1},
			Options: map[protocol.Option]bool{
				protocol.OptionAuthenticatorConfig: true,
				protocol.OptionSetMinPINLength:     true,
				protocol.OptionClientPIN:           true,
			},
		})

		err := d.SetMinPINLength(testContext, nil, protocol.SetMinPINLengthConfigSubCommandParams{
			NewMinPINLength: new(uint(8)),
		})
		if err, target := err, ErrPinUvAuthTokenRequired; !errors.Is(err, target) {
			t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
		}

		assertNoAuthenticatorIO(t, fake)
	})

	t.Run("setMinPINLength option is required", func(t *testing.T) {
		fake := testhid.NewCBORDevice(t, testCID)
		d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
			Versions: protocol.Versions{protocol.FIDO_2_1},
			Options: map[protocol.Option]bool{
				protocol.OptionAuthenticatorConfig: true,
			},
		})

		err := d.SetMinPINLength(testContext, nil, protocol.SetMinPINLengthConfigSubCommandParams{
			NewMinPINLength: new(uint(8)),
		})
		if err, target := err, ErrNotSupported; !errors.Is(err, target) {
			t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
		}

		assertNoAuthenticatorIO(t, fake)
	})

	t.Run("FIDO 2.3 command list is authoritative", func(t *testing.T) {
		fake := testhid.NewCBORDevice(t, testCID)
		d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
			Versions: protocol.Versions{protocol.FIDO_2_3},
			Options: map[protocol.Option]bool{
				protocol.OptionAuthenticatorConfig: true,
				protocol.OptionSetMinPINLength:     true,
			},
			AuthenticatorConfigCommands: []protocol.ConfigSubCommand{},
		})

		err := d.SetMinPINLength(testContext, nil, protocol.SetMinPINLengthConfigSubCommandParams{
			NewMinPINLength: new(uint(8)),
		})
		if err, target := err, ErrNotSupported; !errors.Is(err, target) {
			t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
		}

		assertNoAuthenticatorIO(t, fake)
	})

	t.Run("FIDO 2.3 missing command list rejects subcommands", func(t *testing.T) {
		fake := testhid.NewCBORDevice(t, testCID)
		d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
			Versions: protocol.Versions{protocol.FIDO_2_3},
			Options: map[protocol.Option]bool{
				protocol.OptionAuthenticatorConfig: true,
				protocol.OptionSetMinPINLength:     true,
			},
		})

		err := d.SetMinPINLength(testContext, nil, protocol.SetMinPINLengthConfigSubCommandParams{
			NewMinPINLength: new(uint(8)),
		})
		if err, target := err, ErrNotSupported; !errors.Is(err, target) {
			t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
		}

		assertNoAuthenticatorIO(t, fake)
	})

	t.Run("FIDO 2.1 ignores unknown command list field", func(t *testing.T) {
		info := protocol.AuthenticatorGetInfoResponse{
			Versions: protocol.Versions{protocol.FIDO_2_1},
			Options: map[protocol.Option]bool{
				protocol.OptionAuthenticatorConfig: true,
				protocol.OptionSetMinPINLength:     true,
			},
			AuthenticatorConfigCommands: []protocol.ConfigSubCommand{},
		}
		fake := testhid.NewCBORDevice(t, testCID, nil, encodeCBOR(t, info))
		d := newTestDevice(t, fake, info)

		if err := d.SetMinPINLength(testContext, nil, protocol.SetMinPINLengthConfigSubCommandParams{
			NewMinPINLength: new(uint(8)),
		}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("unprotected alwaysUv can be disabled without auth", func(t *testing.T) {
		info := protocol.AuthenticatorGetInfoResponse{
			Versions: protocol.Versions{protocol.FIDO_2_3},
			Options: map[protocol.Option]bool{
				protocol.OptionAuthenticatorConfig: true,
				protocol.OptionAlwaysUv:            true,
			},
			AuthenticatorConfigCommands: []protocol.ConfigSubCommand{protocol.ConfigSubCommandToggleAlwaysUv},
		}
		fake := testhid.NewCBORDevice(t, testCID, nil, encodeCBOR(t, info))
		d := newTestDevice(t, fake, info)

		if err := d.ToggleAlwaysUV(testContext, nil); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		_, request := fake.FirstCTAPRequestMap(t)
		if _, ok := request[uint64(3)]; ok {
			t.Errorf("value unexpectedly contains %#v", uint64(3))
		}

		if _, ok := request[uint64(4)]; ok {
			t.Errorf("value unexpectedly contains %#v", uint64(4))
		}
	})

	t.Run("enables long touch without requesting getInfo", func(t *testing.T) {
		info := protocol.AuthenticatorGetInfoResponse{
			Versions: protocol.Versions{protocol.FIDO_2_3},
			Options: map[protocol.Option]bool{
				protocol.OptionAuthenticatorConfig: true,
			},
			LongTouchForReset: new(false),
			AuthenticatorConfigCommands: []protocol.ConfigSubCommand{
				protocol.ConfigSubCommandEnableLongTouchForReset,
			},
		}
		fake := testhid.NewCBORDevice(t, testCID, nil)
		d := newTestDevice(t, fake, info)

		if err := d.EnableLongTouchForReset(testContext, nil); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		requests := fake.Requests(t)
		if got, want := len(requests), 1; got != want {
			t.Fatalf("got length %d, want %d", got, want)
		}

		command, request := requests[0].CTAPRequestMap(t)
		if got, want := command, protocol.AuthenticatorConfig; got != want {
			t.Errorf("got %#v, want %#v", got, want)
		}

		if got, want := len(request), 1; got != want {
			t.Errorf("got length %d, want %d", got, want)
		}

		if _, ok := request[uint64(1)]; !ok {
			t.Errorf("value does not contain %#v", uint64(1))
		}
	})

	t.Run("long touch requires feature field", func(t *testing.T) {
		fake := testhid.NewCBORDevice(t, testCID)
		d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
			Versions: protocol.Versions{protocol.FIDO_2_3},
			Options: map[protocol.Option]bool{
				protocol.OptionAuthenticatorConfig: true,
			},
			AuthenticatorConfigCommands: []protocol.ConfigSubCommand{
				protocol.ConfigSubCommandEnableLongTouchForReset,
			},
		})

		err := d.EnableLongTouchForReset(testContext, nil)
		if err, target := err, ErrNotSupported; !errors.Is(err, target) {
			t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
		}

		assertNoAuthenticatorIO(t, fake)
	})

	t.Run("setMinPINLength rejects decreasing minimum", func(t *testing.T) {
		fake := testhid.NewCBORDevice(t, testCID)
		d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
			Versions:     protocol.Versions{protocol.FIDO_2_1},
			MinPINLength: 8,
			Options: map[protocol.Option]bool{
				protocol.OptionAuthenticatorConfig: true,
				protocol.OptionSetMinPINLength:     true,
			},
		})

		err := d.SetMinPINLength(testContext, nil, protocol.SetMinPINLengthConfigSubCommandParams{
			NewMinPINLength: new(uint(7)),
		})
		if err, target := err, SyntaxError; !errors.Is(err, target) {
			t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
		}

		assertNoAuthenticatorIO(t, fake)
	})

	t.Run("setMinPINLength validates RP ID limit", func(t *testing.T) {
		fake := testhid.NewCBORDevice(t, testCID)
		d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
			Versions:                   protocol.Versions{protocol.FIDO_2_1},
			Extensions:                 []extension.ExtensionIdentifier{extension.ExtensionIdentifierMinPinLength},
			MaxRPIDsForSetMinPINLength: new(uint(1)),
			Options: map[protocol.Option]bool{
				protocol.OptionAuthenticatorConfig: true,
				protocol.OptionSetMinPINLength:     true,
			},
		})

		err := d.SetMinPINLength(testContext, nil, protocol.SetMinPINLengthConfigSubCommandParams{
			MinPINLengthRPIDs: []string{"one.example", "two.example"},
		})
		if err, target := err, SyntaxError; !errors.Is(err, target) {
			t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
		}

		assertNoAuthenticatorIO(t, fake)
	})

	t.Run("setMinPINLength requires complexity feature", func(t *testing.T) {
		fake := testhid.NewCBORDevice(t, testCID)
		d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
			Versions: protocol.Versions{protocol.FIDO_2_1},
			Options: map[protocol.Option]bool{
				protocol.OptionAuthenticatorConfig: true,
				protocol.OptionSetMinPINLength:     true,
			},
		})

		err := d.SetMinPINLength(testContext, nil, protocol.SetMinPINLengthConfigSubCommandParams{
			PINComplexityPolicy: true,
		})
		if err, target := err, ErrNotSupported; !errors.Is(err, target) {
			t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
		}

		assertNoAuthenticatorIO(t, fake)
	})
}

func TestGetAssertionRejectsUnadvertisedExtensions(t *testing.T) {
	tests := []struct {
		name      string
		extInputs *webauthn.GetAuthenticationExtensionsClientInputs
	}{
		{
			name: "hmac-secret",
			extInputs: &webauthn.GetAuthenticationExtensionsClientInputs{
				GetHMACSecretInputs: &webauthn.GetHMACSecretInputs{
					HMACGetSecret: webauthn.HMACGetSecretInput{Salt1: make([]byte, 32)},
				},
			},
		},
		{
			name: "credBlob",
			extInputs: &webauthn.GetAuthenticationExtensionsClientInputs{
				GetCredentialBlobInputs: &webauthn.GetCredentialBlobInputs{GetCredBlob: true},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := testhid.NewCBORDevice(t, testCID)
			d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
				Extensions: []extension.ExtensionIdentifier{},
			})

			var gotErr error
			for _, err := range d.GetAssertion(
				testContext,
				nil,
				"example.com",
				[]byte("client-data"),
				nil,
				tt.extInputs,
				nil,
			) {
				gotErr = err
			}

			if err := gotErr; err == nil {
				t.Fatalf("expected an error")
			}

			if got := errors.Is(gotErr, ErrNotSupported); !got {
				t.Errorf("got false, want true")
			}

			assertNoAuthenticatorIO(t, fake)
		})
	}
}

func TestGetAssertionRejectsMalformedTokenBeforeExtensionKeyAgreement(t *testing.T) {
	fake := testhid.NewCBORDevice(t, testCID)
	d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
		Versions:           protocol.Versions{protocol.FIDO_2_3},
		Extensions:         []extension.ExtensionIdentifier{extension.ExtensionIdentifierHMACSecret},
		PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolTwo},
		Options: map[protocol.Option]bool{
			protocol.OptionClientPIN: true,
		},
	})
	extInputs := &webauthn.GetAuthenticationExtensionsClientInputs{
		GetHMACSecretInputs: &webauthn.GetHMACSecretInputs{
			HMACGetSecret: webauthn.HMACGetSecretInput{Salt1: make([]byte, 32)},
		},
	}

	var gotErr error
	for _, err := range d.GetAssertion(
		testContext,
		make([]byte, 16),
		"example.com",
		[]byte("client-data"),
		nil,
		extInputs,
		nil,
	) {
		gotErr = err
	}

	if err, target := gotErr, SyntaxError; !errors.Is(err, target) {
		t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
	}

	assertNoAuthenticatorIO(t, fake)
}

func TestRetryQueriesWorkBeforePINOrUVConfiguration(t *testing.T) {
	t.Run("PIN", func(t *testing.T) {
		fake := testhid.NewCBORDevice(t, testCID, encodeCBOR(t, protocol.AuthenticatorClientPINResponse{
			PinRetries: new(uint(8)),
		}))
		d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
			PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolTwo},
			Options: map[protocol.Option]bool{
				protocol.OptionClientPIN: false,
			},
		})

		retries, _, err := d.GetPINRetries(testContext)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if got, want := retries, uint(8); got != want {
			t.Errorf("got %#v, want %#v", got, want)
		}
	})

	t.Run("UV", func(t *testing.T) {
		fake := testhid.NewCBORDevice(t, testCID, encodeCBOR(t, protocol.AuthenticatorClientPINResponse{
			UvRetries: new(uint(5)),
		}))
		d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
			Versions:           protocol.Versions{protocol.FIDO_2_1},
			PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolTwo},
			Options: map[protocol.Option]bool{
				protocol.OptionUserVerification: false,
			},
		})

		retries, err := d.GetUVRetries(testContext)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if got, want := retries, uint(5); got != want {
			t.Errorf("got %#v, want %#v", got, want)
		}

		command, request := fake.FirstCTAPRequestMap(t)
		if got, want := command, protocol.AuthenticatorClientPIN; got != want {
			t.Errorf("got %#v, want %#v", got, want)
		}
		{
			want, got := uint64(protocol.PinUvAuthProtocolTwo), request[uint64(1)]
			gotValue, ok := got.(uint64)

			if !ok || gotValue != want {
				t.Errorf("got %#v, want %#v", got, want)
			}
		}
		{
			want, got := uint64(protocol.ClientPINSubCommandGetUVRetries), request[uint64(2)]
			gotValue, ok := got.(uint64)

			if !ok || gotValue != want {
				t.Errorf("got %#v, want %#v", got, want)
			}
		}
	})

	t.Run("UV without pinUvAuthProtocol", func(t *testing.T) {
		fake := testhid.NewCBORDevice(t, testCID, encodeCBOR(t, protocol.AuthenticatorClientPINResponse{
			UvRetries: new(uint(5)),
		}))
		d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
			Versions: protocol.Versions{protocol.FIDO_2_1},
			Options: map[protocol.Option]bool{
				protocol.OptionUserVerification: false,
			},
		})

		retries, err := d.GetUVRetries(testContext)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if got, want := retries, uint(5); got != want {
			t.Errorf("got %#v, want %#v", got, want)
		}

		_, request := fake.FirstCTAPRequestMap(t)

		_, present := request[uint64(1)]
		if got := present; got {
			t.Errorf("got true, want false")
		}
	})
}

func TestFIDO20RejectsCTAP21OnlyCommands(t *testing.T) {
	t.Run("getUVRetries", func(t *testing.T) {
		fake := testhid.NewCBORDevice(t, testCID)
		d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
			Versions: protocol.Versions{protocol.FIDO_2_0},
			Options: map[protocol.Option]bool{
				protocol.OptionUserVerification: true,
			},
		})

		_, err := d.GetUVRetries(testContext)
		if err, target := err, ErrNotSupported; !errors.Is(err, target) {
			t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
		}

		assertNoAuthenticatorIO(t, fake)
	})

	t.Run("authenticatorSelection", func(t *testing.T) {
		fake := testhid.NewCBORDevice(t, testCID)
		d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
			Versions: protocol.Versions{protocol.FIDO_2_0},
		})

		err := d.Selection(testContext)
		if err, target := err, ErrNotSupported; !errors.Is(err, target) {
			t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
		}

		assertNoAuthenticatorIO(t, fake)
	})
}

func TestValidateMakeCredentialAuthorization(t *testing.T) {
	tests := []struct {
		name    string
		info    protocol.AuthenticatorGetInfoResponse
		token   []byte
		options map[protocol.Option]bool
		wantErr error
	}{
		{
			name: "FIDO 2.0 unprotected authenticator",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_0},
			},
		},
		{
			name: "FIDO 2.0 configured PIN requires authorization",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_0},
				Options: map[protocol.Option]bool{
					protocol.OptionClientPIN: true,
				},
			},
			wantErr: ErrPinUvAuthTokenRequired,
		},
		{
			name: "FIDO 2.0 configured built-in UV requires authorization",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_0},
				Options: map[protocol.Option]bool{
					protocol.OptionUserVerification: true,
				},
			},
			wantErr: ErrPinUvAuthTokenRequired,
		},
		{
			name: "FIDO 2.0 token satisfies authorization",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_0},
				Options: map[protocol.Option]bool{
					protocol.OptionClientPIN: true,
				},
			},
			token: []byte("token"),
		},
		{
			name: "FIDO 2.0 built-in UV satisfies authorization",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_0},
				Options: map[protocol.Option]bool{
					protocol.OptionUserVerification: true,
				},
			},
			options: map[protocol.Option]bool{
				protocol.OptionUserVerification: true,
			},
		},
		{
			name: "FIDO 2.0 ignores makeCredUvNotRqd",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_0},
				Options: map[protocol.Option]bool{
					protocol.OptionClientPIN:                   true,
					protocol.OptionMakeCredentialUvNotRequired: true,
				},
			},
			wantErr: ErrPinUvAuthTokenRequired,
		},
		{
			name: "FIDO 2.0 ignores alwaysUv",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_0},
				Options: map[protocol.Option]bool{
					protocol.OptionAlwaysUv: true,
				},
			},
		},
		{
			name: "FIDO 2.1 configured PIN requires authorization by default",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_1},
				Options: map[protocol.Option]bool{
					protocol.OptionClientPIN: true,
				},
			},
			wantErr: ErrPinUvAuthTokenRequired,
		},
		{
			name: "FIDO 2.1 token satisfies default requirement",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_1},
				Options: map[protocol.Option]bool{
					protocol.OptionClientPIN: true,
				},
			},
			token: []byte("token"),
		},
		{
			name: "FIDO 2.1 non-discoverable credential may omit authorization",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_1},
				Options: map[protocol.Option]bool{
					protocol.OptionClientPIN:                   true,
					protocol.OptionMakeCredentialUvNotRequired: true,
				},
			},
		},
		{
			name: "FIDO 2.1 discoverable credential still requires authorization",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_1},
				Options: map[protocol.Option]bool{
					protocol.OptionClientPIN:                   true,
					protocol.OptionMakeCredentialUvNotRequired: true,
				},
			},
			options: map[protocol.Option]bool{
				protocol.OptionResidentKeys: true,
			},
			wantErr: ErrPinUvAuthTokenRequired,
		},
		{
			name: "FIDO 2.1 always UV requires authorization without built-in UV",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_1},
				Options: map[protocol.Option]bool{
					protocol.OptionAlwaysUv:  true,
					protocol.OptionClientPIN: true,
				},
			},
			wantErr: ErrPinUvAuthTokenRequired,
		},
		{
			name: "FIDO 2.1 always UV implicitly uses configured built-in UV",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_1},
				Options: map[protocol.Option]bool{
					protocol.OptionAlwaysUv:         true,
					protocol.OptionUserVerification: true,
				},
			},
		},
		{
			name: "FIDO 2.3 uses modern makeCredUvNotRqd semantics",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_3},
				Options: map[protocol.Option]bool{
					protocol.OptionClientPIN:                   true,
					protocol.OptionMakeCredentialUvNotRequired: true,
				},
			},
		},
		{
			name: "FIDO 2.3 discoverable credential still requires authorization",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_3},
				Options: map[protocol.Option]bool{
					protocol.OptionClientPIN:                   true,
					protocol.OptionMakeCredentialUvNotRequired: true,
				},
			},
			options: map[protocol.Option]bool{
				protocol.OptionResidentKeys: true,
			},
			wantErr: ErrPinUvAuthTokenRequired,
		},
		{
			name: "device supporting FIDO 2.0 and 2.1 uses modern semantics",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_0, protocol.FIDO_2_1},
				Options: map[protocol.Option]bool{
					protocol.OptionClientPIN:                   true,
					protocol.OptionMakeCredentialUvNotRequired: true,
				},
			},
		},
		{
			name: "FIDO 2.1 preview uses modern semantics",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_0, protocol.FIDO_2_1_PRE},
				Options: map[protocol.Option]bool{
					protocol.OptionClientPIN:                   true,
					protocol.OptionMakeCredentialUvNotRequired: true,
				},
			},
		},
		{
			name: "unknown future FIDO version uses modern semantics",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_0, protocol.Version("FIDO_2_4")},
				Options: map[protocol.Option]bool{
					protocol.OptionClientPIN:                   true,
					protocol.OptionMakeCredentialUvNotRequired: true,
				},
			},
		},
		{
			name: "missing versions preserves modern semantics",
			info: protocol.AuthenticatorGetInfoResponse{
				Options: map[protocol.Option]bool{
					protocol.OptionClientPIN:                   true,
					protocol.OptionMakeCredentialUvNotRequired: true,
				},
			},
		},
		{
			name: "built-in UV unsupported",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_1},
			},
			options: map[protocol.Option]bool{
				protocol.OptionUserVerification: true,
			},
			wantErr: ErrNotSupported,
		},
		{
			name: "built-in UV not configured",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_1},
				Options: map[protocol.Option]bool{
					protocol.OptionUserVerification: false,
				},
			},
			options: map[protocol.Option]bool{
				protocol.OptionUserVerification: true,
			},
			wantErr: ErrUvNotConfigured,
		},
		{
			name:  "token and built-in UV are mutually exclusive",
			token: []byte("token"),
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_1},
				Options: map[protocol.Option]bool{
					protocol.OptionUserVerification: true,
				},
			},
			options: map[protocol.Option]bool{
				protocol.OptionUserVerification: true,
			},
			wantErr: SyntaxError,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateMakeCredentialAuthorization(test.info, test.token, test.options)
			if test.wantErr == nil {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}

				return
			}

			if err, target := err, test.wantErr; !errors.Is(err, target) {
				t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
			}
		})
	}
}

func TestValidateGetAssertionAuthorization(t *testing.T) {
	tests := []struct {
		name    string
		info    protocol.AuthenticatorGetInfoResponse
		token   []byte
		options map[protocol.Option]bool
		wantErr error
	}{
		{
			name: "FIDO 2.0 configured PIN does not require authorization",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_0},
				Options: map[protocol.Option]bool{
					protocol.OptionClientPIN: true,
				},
			},
		},
		{
			name: "FIDO 2.0 ignores alwaysUv",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_0, protocol.U2F_V2},
				Options: map[protocol.Option]bool{
					protocol.OptionAlwaysUv:  true,
					protocol.OptionClientPIN: true,
				},
			},
		},
		{
			name: "configured PIN without alwaysUv permits UP-only assertion",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_1},
				Options: map[protocol.Option]bool{
					protocol.OptionClientPIN: true,
				},
			},
		},
		{
			name: "token and built-in UV are mutually exclusive",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_3},
				Options: map[protocol.Option]bool{
					protocol.OptionUserVerification: true,
				},
			},
			token: []byte("token"),
			options: map[protocol.Option]bool{
				protocol.OptionUserVerification: true,
			},
			wantErr: SyntaxError,
		},
		{
			name: "built-in UV unsupported",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_3},
			},
			options: map[protocol.Option]bool{
				protocol.OptionUserVerification: true,
			},
			wantErr: ErrNotSupported,
		},
		{
			name: "built-in UV not configured",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_3},
				Options: map[protocol.Option]bool{
					protocol.OptionUserVerification: false,
				},
			},
			options: map[protocol.Option]bool{
				protocol.OptionUserVerification: true,
			},
			wantErr: ErrUvNotConfigured,
		},
		{
			name: "rk is unsupported even when false",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_3},
			},
			options: map[protocol.Option]bool{
				protocol.OptionResidentKeys: false,
			},
			wantErr: ErrNotSupported,
		},
		{
			name: "FIDO 2.1 alwaysUv requires token for PIN-only authenticator",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_1},
				Options: map[protocol.Option]bool{
					protocol.OptionAlwaysUv:  true,
					protocol.OptionClientPIN: true,
				},
			},
			wantErr: ErrPinUvAuthTokenRequired,
		},
		{
			name: "FIDO 2.3 token satisfies alwaysUv",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_3},
				Options: map[protocol.Option]bool{
					protocol.OptionAlwaysUv:  true,
					protocol.OptionClientPIN: true,
				},
			},
			token: []byte("token"),
		},
		{
			name: "explicit built-in UV satisfies alwaysUv",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_3},
				Options: map[protocol.Option]bool{
					protocol.OptionAlwaysUv:         true,
					protocol.OptionUserVerification: true,
				},
			},
			options: map[protocol.Option]bool{
				protocol.OptionUserVerification: true,
			},
		},
		{
			name: "configured built-in UV is used implicitly for alwaysUv",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_3},
				Options: map[protocol.Option]bool{
					protocol.OptionAlwaysUv:         true,
					protocol.OptionUserVerification: true,
				},
			},
		},
		{
			name: "up false bypasses alwaysUv requirement",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_3},
				Options: map[protocol.Option]bool{
					protocol.OptionAlwaysUv:  true,
					protocol.OptionClientPIN: true,
				},
			},
			options: map[protocol.Option]bool{
				protocol.OptionUserPresence: false,
			},
		},
		{
			name: "alwaysUv reports unconfigured built-in UV",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_3},
				Options: map[protocol.Option]bool{
					protocol.OptionAlwaysUv:         true,
					protocol.OptionUserVerification: false,
				},
			},
			wantErr: ErrUvNotConfigured,
		},
		{
			name: "alwaysUv without available UV mechanism requires built-in UV",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_3},
				Options: map[protocol.Option]bool{
					protocol.OptionAlwaysUv: true,
				},
			},
			wantErr: ErrBuiltInUVRequired,
		},
		{
			name: "client PIN without GetAssertion permission cannot satisfy alwaysUv",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_3},
				Options: map[protocol.Option]bool{
					protocol.OptionAlwaysUv:                       true,
					protocol.OptionClientPIN:                      true,
					protocol.OptionNoMcGaPermissionsWithClientPin: true,
				},
			},
			wantErr: ErrBuiltInUVRequired,
		},
		{
			name: "device supporting FIDO 2.0 and 2.1 uses modern semantics",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_0, protocol.FIDO_2_1},
				Options: map[protocol.Option]bool{
					protocol.OptionAlwaysUv:  true,
					protocol.OptionClientPIN: true,
				},
			},
			wantErr: ErrPinUvAuthTokenRequired,
		},
		{
			name: "missing versions preserves modern semantics",
			info: protocol.AuthenticatorGetInfoResponse{
				Options: map[protocol.Option]bool{
					protocol.OptionAlwaysUv:  true,
					protocol.OptionClientPIN: true,
				},
			},
			wantErr: ErrPinUvAuthTokenRequired,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateGetAssertionAuthorization(test.info, test.token, test.options)
			if test.wantErr == nil {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}

				return
			}

			if err, target := err, test.wantErr; !errors.Is(err, target) {
				t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
			}
		})
	}
}

func TestGetAssertionValidatesAuthorizationBeforeCommand(t *testing.T) {
	fake := testhid.NewCBORDevice(t, testCID)
	d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
		Versions: protocol.Versions{protocol.FIDO_2_3},
		Options: map[protocol.Option]bool{
			protocol.OptionAlwaysUv:  true,
			protocol.OptionClientPIN: true,
		},
	})

	var count int
	for assertion, err := range d.GetAssertion(
		testContext,
		nil,
		"example.com",
		[]byte("client-data"),
		nil,
		nil,
		nil,
	) {
		count++

		if !assertionResponseIsZero(assertion) {
			t.Errorf("got %#v, want zero response", assertion)
		}

		if err, target := err, ErrPinUvAuthTokenRequired; !errors.Is(err, target) {
			t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
		}
	}

	if got, want := count, 1; got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}

	assertNoAuthenticatorIO(t, fake)
}
