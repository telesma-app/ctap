package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"time"

	gble "github.com/telesma-app/ble"
	ctapauthenticator "github.com/telesma-app/ctap/authenticator"
	ctapblebackend "github.com/telesma-app/ctap/backend/ble"
)

var (
	scanDuration         = flag.Duration("scan", 5*time.Second, "BLE scan window")
	peripheralIdentifier = flag.String("id", "", "CoreBluetooth peripheral identifier")
)

func main() {
	flag.Parse()
	if err := run(context.Background()); err != nil {
		log.Fatal(err)
	}
}

func run(ctx context.Context) error {
	scanCtx, cancelScan := context.WithTimeout(ctx, *scanDuration)
	defer cancelScan()

	var advertisements []*gble.DeviceInfo
	for advertisement, err := range ctapblebackend.Devices(scanCtx) {
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) && errors.Is(scanCtx.Err(), context.DeadlineExceeded) {
				break
			}
			return err
		}
		advertisements = append(advertisements, advertisement)
		fmt.Printf("%s\t%s\tRSSI %d dBm\n", advertisement.ID, advertisement.Name, advertisement.RSSI)
	}

	identifier := gble.Identifier(*peripheralIdentifier)
	if identifier == "" {
		switch len(advertisements) {
		case 0:
			return errors.New("no FIDO BLE authenticators found")
		case 1:
			identifier = advertisements[0].ID
		default:
			return errors.New("multiple authenticators found; select one with -id")
		}
	}

	transport, err := ctapblebackend.Open(ctx, identifier)
	if err != nil {
		return err
	}
	authenticator, err := ctapauthenticator.New(ctx, transport)
	if err != nil {
		return errors.Join(err, transport.Close())
	}
	defer authenticator.Close()

	info, _ := authenticator.GetInfoCached()
	encoded, err := json.MarshalIndent(info, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(encoded))
	return nil
}
