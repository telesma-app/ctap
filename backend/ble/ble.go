// Package ble connects FIDO Bluetooth Low Energy peripherals to the CTAP
// transport abstraction.
package ble

import (
	"context"
	"errors"
	"iter"
	"time"

	gble "github.com/telesma-app/ble"
	"github.com/telesma-app/ctap/backend"
	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/ctap/transport/ctapble"
)

const fidoServiceUUID16 = 0xfffd

// Devices scans for peripherals advertising the FIDO service until ctx is
// canceled or the iterator consumer stops.
func Devices(ctx context.Context) iter.Seq2[*gble.DeviceInfo, error] {
	return gble.Scan(ctx, gble.UUID16(fidoServiceUUID16))
}

// Open connects to id and initializes its CTAP BLE transport. The returned
// transport owns the peripheral connection.
func Open(ctx context.Context, id gble.Identifier) (*ctapble.Transport, error) {
	return openWith(ctx, id, gble.Open)
}

func openWith(
	ctx context.Context,
	id gble.Identifier,
	openPeripheral func(context.Context, gble.Identifier) (gble.Peripheral, error),
) (*ctapble.Transport, error) {
	peripheral, err := openPeripheral(ctx, id)
	if err != nil {
		return nil, err
	}

	transport, err := ctapble.Open(ctx, peripheral)
	if err != nil {
		return nil, errors.Join(err, peripheral.Close())
	}

	return transport, nil
}

// Enumerator returns a CTAP backend which scans for scanDuration, then opens
// each unique candidate in discovery order.
func Enumerator(scanDuration time.Duration) backend.Enumerator {
	return enumerator(scanDuration, Devices, func(ctx context.Context, id gble.Identifier) (ctaptransport.Device, error) {
		return Open(ctx, id)
	})
}

func enumerator(
	scanDuration time.Duration,
	devices func(context.Context) iter.Seq2[*gble.DeviceInfo, error],
	open func(context.Context, gble.Identifier) (ctaptransport.Device, error),
) backend.Enumerator {
	return func(ctx context.Context) iter.Seq2[ctaptransport.Device, error] {
		return func(yield func(ctaptransport.Device, error) bool) {
			if err := ctx.Err(); err != nil {
				yield(nil, err)
				return
			}

			scanCtx, cancel := context.WithTimeout(ctx, scanDuration)
			defer cancel()

			seen := make(map[gble.Identifier]struct{})

			var candidates []gble.Identifier

			for info, err := range devices(scanCtx) {
				if err != nil {
					if ctx.Err() != nil {
						yield(nil, ctx.Err())
						return
					}

					if errors.Is(err, context.DeadlineExceeded) && errors.Is(scanCtx.Err(), context.DeadlineExceeded) {
						break
					}

					yield(nil, err)

					return
				}

				if _, duplicate := seen[info.ID]; duplicate {
					continue
				}

				seen[info.ID] = struct{}{}
				candidates = append(candidates, info.ID)
			}

			for _, id := range candidates {
				if err := ctx.Err(); err != nil {
					yield(nil, err)
					return
				}

				transport, err := open(ctx, id)
				if !yield(transport, err) {
					return
				}
			}
		}
	}
}
