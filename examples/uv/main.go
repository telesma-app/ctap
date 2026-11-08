package main

import (
	"context"
	"fmt"
	"log"

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

	retries, err := device.GetUVRetries(ctx)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("UV retries: %d\n", retries)

	token, err := device.GetPinUvAuthTokenUsingUV(
		ctx,
		protocol.PermissionCredentialManagement|protocol.PermissionBioEnrollment,
		"",
	)
	if err != nil {
		log.Fatal(err)
	}

	printFingerprints(ctx, device, token)
	printCredentials(ctx, device, token)
}

func printFingerprints(ctx context.Context, device *authenticator.Device, token []byte) {
	response, err := device.EnumerateEnrollments(ctx, token)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Fingerprints: %d\n", len(response.TemplateInfos))

	for i, template := range response.TemplateInfos {
		fmt.Printf(
			"%d) %s (template ID: %x)\n",
			i+1,
			template.TemplateFriendlyName,
			template.TemplateID,
		)
	}
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
