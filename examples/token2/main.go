package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/telesma-app/ctap/authenticator"
	"github.com/telesma-app/ctap/backend/token2"
	"github.com/telesma-app/ctap/protocol"
	"github.com/telesma-app/pcsc"
)

func main() {
	if err := run(context.Background()); err != nil {
		log.Fatal(err)
	}
}

func run(ctx context.Context) (err error) {
	readerName, err := findReader(os.Getenv("PCSC_READER"))
	if err != nil {
		return err
	}

	transport, err := token2.Open(ctx, readerName)
	if err != nil {
		return err
	}

	device, err := authenticator.New(ctx, transport)
	if err != nil {
		return errors.Join(err, transport.Close())
	}
	defer func() {
		err = errors.Join(err, device.Close())
	}()

	pin := os.Getenv("FIDO2_PIN")
	if pin == "" {
		return errors.New("FIDO2_PIN is not set")
	}

	token, err := device.GetPinUvAuthTokenUsingPIN(
		ctx,
		pin,
		protocol.PermissionCredentialManagement,
		"",
	)
	if err != nil {
		return err
	}

	fmt.Printf("PC/SC reader: %s\n", readerName)

	return printCredentials(ctx, device, token)
}

func findReader(filter string) (string, error) {
	for reader, err := range pcsc.Enumerate() {
		if err != nil {
			return "", err
		}

		if filter == "" {
			return reader.Name, nil
		}

		if strings.Contains(reader.Name, filter) {
			return reader.Name, nil
		}
	}

	return "", fmt.Errorf("no PC/SC reader matching %q", filter)
}

func printCredentials(ctx context.Context, device *authenticator.Device, token []byte) error {
	metadata, err := device.GetCredsMetadata(ctx, token)
	if err != nil {
		return err
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
			return err
		}

		rps = append(rps, rp)
	}

	index := 1

	for _, rp := range rps {
		for credential, err := range device.EnumerateCredentials(ctx, token, rp.RPIDHash) {
			if err != nil {
				return err
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

	return nil
}
