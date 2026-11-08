package main

import (
	"context"
	"fmt"
	"log"

	"github.com/telesma-app/ctap/authenticator"
	"github.com/telesma-app/ctap/backend"
	directhid "github.com/telesma-app/ctap/backend/hid"
	"github.com/telesma-app/ctap/backend/hidproxy"
	ctappcsc "github.com/telesma-app/ctap/backend/pcsc"
	"github.com/telesma-app/ctap/backend/token2"
	"github.com/telesma-app/ctap/diagnostic"
	"github.com/telesma-app/ctap/options"
	"github.com/telesma-app/ctap/protocol"
)

type source struct {
	name      string
	enumerate backend.Enumerator
}

var sources = []source{
	{name: "Direct HID", enumerate: directhid.Enumerate},
	{name: "Windows HID proxy", enumerate: hidproxy.Enumerate},
	{name: "Standard FIDO over PC/SC", enumerate: ctappcsc.Enumerate},
	{name: "Token2 proprietary over PC/SC", enumerate: token2.Enumerate},
}

func main() {
	if err := run(context.Background()); err != nil {
		log.Fatal(err)
	}
}

func run(ctx context.Context) error {
	for _, source := range sources {
		fmt.Printf("\n=== %s ===\n", source.name)

		count := 0

		for deviceTransport, err := range source.enumerate(ctx) {
			if err != nil {
				fmt.Printf("error: %v\n", err)
				continue
			}

			count++
			fmt.Printf("\n--- authenticator %d ---\n", count)

			device, err := authenticator.New(
				ctx,
				deviceTransport,
				options.WithDiagnosticSink(printGetInfo),
			)
			if err != nil {
				if closeErr := deviceTransport.Close(); closeErr != nil {
					fmt.Printf("close failed: %v\n", closeErr)
				}

				continue
			}

			if err := device.Close(); err != nil {
				fmt.Printf("close failed: %v\n", err)
			}
		}

		if count == 0 {
			fmt.Println("no authenticators")
		}
	}

	return nil
}

func printGetInfo(_ context.Context, exchange diagnostic.Exchange) {
	if exchange.Command != protocol.AuthenticatorGetInfo {
		return
	}

	if exchange.Err != nil {
		fmt.Printf("getInfo failed: %v\n", exchange.Err)
		return
	}

	if exchange.Status != nil {
		fmt.Printf("status: %s\n", exchange.Status.String())
	}

	if exchange.Response.Notation == "" {
		fmt.Println("{}")
		return
	}

	fmt.Println(exchange.Response.Notation)
}
