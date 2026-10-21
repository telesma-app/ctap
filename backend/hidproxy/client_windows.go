//go:build windows

package hidproxy

import (
	"context"
	"io"
	"iter"

	"github.com/Microsoft/go-winio"
	"github.com/fxamacker/cbor/v2"
	"github.com/telesma-app/ctap/transport/ctaphid"
	ghid "github.com/telesma-app/hid"
	proxyprotocol "github.com/telesma-app/windows-proxy/protocol"
)

// Devices returns HID authenticators and descriptor read outcomes from the proxy.
func Devices(ctx context.Context) iter.Seq2[*ghid.DeviceInfo, error] {
	return func(yield func(*ghid.DeviceInfo, error) bool) {
		pipe, err := winio.DialPipeContext(ctx, proxyprotocol.NamedPipePath)
		if err != nil {
			yield(nil, err)
			return
		}
		defer pipe.Close()

		message, err := proxyprotocol.NewMessage(proxyprotocol.CommandEnumerate, nil)
		if err != nil {
			yield(nil, err)
			return
		}
		err = withContextIO(ctx, pipe, func() error {
			if _, writeErr := message.WriteTo(pipe); writeErr != nil {
				return writeErr
			}

			message, err = proxyprotocol.ParseMessage(pipe)
			return err
		})
		if err != nil {
			yield(nil, err)
			return
		}

		var devices proxyprotocol.Enumeration
		if err := cbor.Unmarshal(message.Data, &devices); err != nil {
			yield(nil, err)
			return
		}

		for _, device := range devices {
			if err := ctx.Err(); err != nil {
				yield(nil, err)
				return
			}
			if !yield(device.DeviceInfo, device.MetadataErr) {
				return
			}
		}
	}
}

type DeviceEvent struct {
	Err error
}

// Events reports when the proxy's HID device topology may have changed.
func Events(ctx context.Context) (<-chan DeviceEvent, error) {
	pipe, err := winio.DialPipeContext(ctx, proxyprotocol.NamedPipePath)
	if err != nil {
		return nil, err
	}

	message, err := proxyprotocol.NewMessage(proxyprotocol.CommandDevicesChanged, nil)
	if err != nil {
		_ = pipe.Close()
		return nil, err
	}

	if err := withContextIO(ctx, pipe, func() error {
		_, writeErr := message.WriteTo(pipe)
		return writeErr
	}); err != nil {
		_ = pipe.Close()
		return nil, err
	}

	events := make(chan DeviceEvent)
	go func() {
		defer close(events)
		defer pipe.Close()

		stop := context.AfterFunc(ctx, func() { _ = pipe.Close() })
		defer stop()

		for {
			event, err := proxyprotocol.ParseMessage(pipe)
			if err != nil {
				if ctx.Err() == nil {
					select {
					case events <- DeviceEvent{Err: err}:
					case <-ctx.Done():
					}
				}
				return
			}

			if event.Command != proxyprotocol.CommandDevicesChanged {
				continue
			}

			select {
			case events <- DeviceEvent{}:
			case <-ctx.Done():
				return
			}
		}
	}()

	return events, nil
}

func openPath(ctx context.Context, path string) (ctaphid.Device, error) {
	pipe, err := winio.DialPipeContext(ctx, proxyprotocol.NamedPipePath)
	if err != nil {
		return nil, err
	}

	message, err := proxyprotocol.NewMessage(proxyprotocol.CommandStart, path)
	if err != nil {
		_ = pipe.Close()
		return nil, err
	}

	if err := withContextIO(ctx, pipe, func() error {
		_, writeErr := message.WriteTo(pipe)
		return writeErr
	}); err != nil {
		_ = pipe.Close()
		return nil, err
	}

	return &contextDevice{ReadWriteCloser: pipe}, nil
}

type contextDevice struct {
	io.ReadWriteCloser
}

func (d *contextDevice) Read(ctx context.Context, p []byte) (n int, err error) {
	err = withContextIO(ctx, d, func() error {
		n, err = d.ReadWriteCloser.Read(p)
		return err
	})
	return n, err
}

func (d *contextDevice) Write(ctx context.Context, p []byte) (n int, err error) {
	err = withContextIO(ctx, d, func() error {
		n, err = d.ReadWriteCloser.Write(p)
		return err
	})
	return n, err
}
