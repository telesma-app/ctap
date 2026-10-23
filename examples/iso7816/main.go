package main

import (
	"context"
	"errors"
	"fmt"
	"log"

	"github.com/telesma-app/ctap/authenticator"
	ctappcsc "github.com/telesma-app/ctap/backend/pcsc"
)

func main() {
	if err := run(context.Background()); err != nil {
		log.Fatal(err)
	}
}

func run(ctx context.Context) (err error) {
	device, err := authenticator.Select(ctx, ctappcsc.Enumerate)
	if err != nil {
		return err
	}
	defer func() {
		err = errors.Join(err, device.Close())
	}()

	info, _ := device.GetInfoCached()

	fmt.Printf("CTAP versions: %v\n", info.Versions)
	fmt.Printf("AAGUID: %s\n", info.AAGUID)
	fmt.Printf("Options: %v\n", info.Options)
	return nil
}
