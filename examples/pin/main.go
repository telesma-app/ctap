package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/telesma-app/ctap/authenticator"
	directhid "github.com/telesma-app/ctap/backend/hid"
	"github.com/telesma-app/ctap/protocol"
)

func main() {
	ctx := context.Background()

	device, err := authenticator.Select(
		ctx,
		directhid.Enumerate,
	)
	if err != nil {
		log.Fatal(err)
	}

	defer func() {
		_ = device.Close()
	}()

	pin := os.Getenv("FIDO2_PIN")
	if pin == "" {
		log.Fatal("FIDO2_PIN is not set")
	}

	retries, powerCycleRequired, err := device.GetPINRetries(ctx)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("PIN retries: %d", retries)

	if powerCycleRequired != nil {
		fmt.Printf("; power cycle required: %t", *powerCycleRequired)
	}

	fmt.Println()

	token, err := device.GetPinUvAuthTokenUsingPIN(
		ctx,
		pin,
		protocol.PermissionCredentialManagement,
		"",
	)
	if err != nil {
		log.Fatal(err)
	}

	printCredentials(ctx, device, token)
}

func printCredentials(ctx context.Context, device *authenticator.Device, token []byte) {
	metadata, err := device.GetCredsMetadata(ctx, token)
	if err != nil {
		log.Fatal(err)
	}

	existing, remaining := uint(0), uint(0)
	if metadata.ExistingResidentCredentialsCount != nil {
		existing = *metadata.ExistingResidentCredentialsCount
	}

	if metadata.MaxPossibleRemainingResidentCredentialsCount != nil {
		remaining = *metadata.MaxPossibleRemainingResidentCredentialsCount
	}

	fmt.Printf(
		"Passkeys: %d (%d slots left)\n",
		existing,
		remaining,
	)

	rps := make([]protocol.AuthenticatorCredentialManagementResponse, 0)

	for rp, err := range device.EnumerateRPs(ctx, token) {
		if err != nil {
			log.Fatal(err)
		}

		rps = append(rps, rp)
	}

	index := 1

	for _, rp := range rps {
		for credential, err := range device.EnumerateCredentials(ctx, token, rp.RPIDHash) {
			if err != nil {
				log.Fatal(err)
			}

			fmt.Printf(
				"%d) %s: %s / %s / %s\n",
				index,
				rp.RP.ID,
				string(credential.User.ID),
				credential.User.Name,
				credential.User.DisplayName,
			)
			index++
		}
	}
}
