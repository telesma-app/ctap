package authenticator

import (
	"context"
	"errors"

	"github.com/telesma-app/ctap/backend"
	"github.com/telesma-app/ctap/options"
)

// Select returns the only authenticator or asks for user presence concurrently
// when several authenticators are available. It closes every device except the
// selected one.
func Select(
	ctx context.Context,
	enumerate backend.Enumerator,
	opts ...options.Option,
) (*Device, error) {
	var (
		devices      []*Device
		candidateErr error
	)

	for deviceTransport, err := range enumerate(ctx) {
		if err != nil {
			candidateErr = errors.Join(candidateErr, err)
			continue
		}

		device, err := New(ctx, deviceTransport, opts...)
		if err != nil {
			candidateErr = errors.Join(candidateErr, err, deviceTransport.Close())
			continue
		}

		devices = append(devices, device)
	}

	switch len(devices) {
	case 0:
		return nil, errors.Join(errors.New("no authenticators found"), candidateErr)
	case 1:
		return devices[0], nil
	}

	type result struct {
		device *Device
		err    error
	}

	selectionCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	results := make(chan result, len(devices))
	for _, device := range devices {
		go func() {
			results <- result{device: device, err: device.Selection(selectionCtx)}
		}()
	}

	var selectionErr error

	for range devices {
		select {
		case <-ctx.Done():
			cancel()
			return nil, errors.Join(ctx.Err(), closeDevices(devices, nil))

		case result := <-results:
			if result.err != nil {
				selectionErr = errors.Join(selectionErr, result.err)
				continue
			}

			cancel()

			if err := closeDevices(devices, result.device); err != nil {
				return nil, errors.Join(err, result.device.Close())
			}

			return result.device, nil
		}
	}

	return nil, errors.Join(candidateErr, selectionErr, closeDevices(devices, nil))
}

func closeDevices(devices []*Device, except *Device) error {
	var closeErr error

	for _, device := range devices {
		if device != except {
			closeErr = errors.Join(closeErr, device.Close())
		}
	}

	return closeErr
}
