package ble_test

import (
	"context"
	"os"
	"testing"
	"time"

	gble "github.com/telesma-app/ble"
	ctapauthenticator "github.com/telesma-app/ctap/authenticator"
	ctapblebackend "github.com/telesma-app/ctap/backend/ble"
)

func TestHardwareGetInfo(t *testing.T) {
	if os.Getenv("CTAP_BLE_TEST") != "1" {
		t.Skip("set CTAP_BLE_TEST=1 to test a BLE authenticator")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	identifier := gble.Identifier(os.Getenv("CTAP_BLE_DEVICE_ID"))
	if identifier == "" {
		scanCtx, stopScan := context.WithTimeout(ctx, 8*time.Second)
		defer stopScan()

		for advertisement, err := range ctapblebackend.Devices(scanCtx) {
			if err != nil {
				if scanCtx.Err() != nil {
					break
				}

				t.Fatal(err)
			}

			if identifier != "" {
				t.Fatalf("multiple authenticators found; set CTAP_BLE_DEVICE_ID (at least %s and %s)", identifier, advertisement.ID)
			}

			identifier = advertisement.ID
		}
	}

	if identifier == "" {
		t.Fatal("no BLE authenticator found")
	}

	transport, err := ctapblebackend.Open(ctx, identifier)
	if err != nil {
		t.Fatal(err)
	}

	authenticator, err := ctapauthenticator.New(ctx, transport)
	if err != nil {
		_ = transport.Close()

		t.Fatal(err)
	}
	defer func() { _ = authenticator.Close() }()

	if _, ok := authenticator.GetInfoCached(); !ok {
		t.Fatal("authenticatorGetInfo response was not cached")
	}
}
