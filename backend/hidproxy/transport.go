package hidproxy

import (
	"context"
	"errors"
	"iter"

	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/ctap/transport/ctaphid"
	ghid "github.com/telesma-app/hid"
)

var ErrNotSupported = errors.New("hidproxy: not supported on this platform")

// Enumerate opens proxy FIDO endpoints even when their metadata is incomplete.
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

// Open starts a proxy session, allocates a CTAPHID channel, and returns an
// initialized transport. The returned transport owns the pipe connection.
func Open(ctx context.Context, path string) (*ctaphid.Transport, error) {
	device, err := openPath(ctx, path)
	if err != nil {
		return nil, err
	}

	transport, err := ctaphid.Open(ctx, device)
	if err != nil {
		return nil, errors.Join(err, device.Close())
	}

	return transport, nil
}
