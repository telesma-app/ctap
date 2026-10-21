// Package hid connects platform HID endpoints to the CTAPHID transport.
package hid

import (
	"context"
	"errors"
	"iter"

	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/ctap/transport/ctaphid"
	ghid "github.com/telesma-app/hid"
)

// Devices returns FIDO HID endpoints, including incomplete descriptor metadata.
func Devices(ctx context.Context) iter.Seq2[*ghid.DeviceInfo, error] {
	return func(yield func(*ghid.DeviceInfo, error) bool) {
		if err := ctx.Err(); err != nil {
			yield(nil, err)
			return
		}

		for info, err := range ghid.Enumerate(
			ghid.WithUsagePage(0xf1d0),
			ghid.WithUsage(0x01),
		) {
			if err := ctx.Err(); err != nil {
				yield(nil, err)
				return
			}
			if !yield(info, err) {
				return
			}
		}
	}
}

// Enumerate opens FIDO HID endpoints even when their metadata is incomplete.
func Enumerate(ctx context.Context) iter.Seq2[ctaptransport.Device, error] {
	return enumerate(ctx, Devices(ctx), Open)
}

func enumerate(
	ctx context.Context,
	devices iter.Seq2[*ghid.DeviceInfo, error],
	open func(context.Context, string) (*ctaphid.Transport, error),
) iter.Seq2[ctaptransport.Device, error] {
	return func(yield func(ctaptransport.Device, error) bool) {
		for info, err := range devices {
			if info == nil {
				if !yield(nil, err) {
					return
				}
				continue
			}

			transport, err := open(ctx, info.Path)
			if err != nil {
				if !yield(nil, err) {
					return
				}
				continue
			}
			if !yield(transport, nil) {
				return
			}
		}
	}
}

// Open opens a FIDO HID endpoint and returns an owned CTAPHID transport.
func Open(ctx context.Context, path string) (*ctaphid.Transport, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	device, err := ghid.OpenPath(path)
	if err != nil {
		return nil, err
	}

	transport, err := ctaphid.Open(ctx, device)
	if err != nil {
		return nil, errors.Join(err, device.Close())
	}

	return transport, nil
}
