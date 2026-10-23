// Package tcp connects CTAPHID report streams exposed over TCP by emulators
// and proxies. It is not a FIDO transport: the stream carries complete
// 64-byte CTAPHID reports without USB framing.
package tcp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/telesma-app/ctap/transport/ctaphid"
)

const (
	inputReportSize  = 64
	outputReportSize = inputReportSize + 1
)

// Device is a raw CTAPHID report stream over TCP.
type Device struct {
	conn    net.Conn
	readMu  sync.Mutex
	writeMu sync.Mutex
}

var _ ctaphid.Device = (*Device)(nil)

// Dial connects to a raw CTAPHID report stream.
func Dial(ctx context.Context, address string) (*Device, error) {
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}

	return &Device{conn: conn}, nil
}

// Open connects to a raw CTAPHID report stream and allocates a channel. The
// returned transport owns the connection.
func Open(ctx context.Context, address string) (*ctaphid.Transport, error) {
	device, err := Dial(ctx, address)
	if err != nil {
		return nil, err
	}

	transport, err := ctaphid.Open(ctx, device)
	if err != nil {
		return nil, errors.Join(err, device.Close())
	}

	return transport, nil
}

// Read reads one complete 64-byte CTAPHID input report.
func (d *Device) Read(ctx context.Context, report []byte) (int, error) {
	if len(report) != inputReportSize {
		return 0, fmt.Errorf("tcp: input report must be %d bytes, got %d", inputReportSize, len(report))
	}

	d.readMu.Lock()
	defer d.readMu.Unlock()

	n, err := interruptOnCancel(ctx, d.conn.SetReadDeadline, func() (int, error) {
		return io.ReadFull(d.conn, report)
	})

	return n, err
}

// Write writes one 65-byte HID output report after removing its zero report ID.
func (d *Device) Write(ctx context.Context, report []byte) (int, error) {
	if len(report) != outputReportSize {
		return 0, fmt.Errorf("tcp: output report must be %d bytes, got %d", outputReportSize, len(report))
	}

	if report[0] != 0 {
		return 0, fmt.Errorf("tcp: output report ID must be zero, got %d", report[0])
	}

	d.writeMu.Lock()
	defer d.writeMu.Unlock()

	n, err := interruptOnCancel(ctx, d.conn.SetWriteDeadline, func() (int, error) {
		return writeFull(d.conn, report[1:])
	})

	return n + 1, err
}

// Close closes the report stream and unblocks pending I/O.
func (d *Device) Close() error {
	return d.conn.Close()
}

func interruptOnCancel(
	ctx context.Context,
	setDeadline func(time.Time) error,
	operation func() (int, error),
) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}

	interrupted := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		_ = setDeadline(time.Now())

		close(interrupted)
	})

	n, err := operation()

	if !stop() {
		<-interrupted
	}

	resetErr := setDeadline(time.Time{})

	if ctxErr := ctx.Err(); ctxErr != nil {
		return n, ctxErr
	}

	return n, errors.Join(err, resetErr)
}

func writeFull(writer io.Writer, data []byte) (int, error) {
	written := 0
	for written < len(data) {
		n, err := writer.Write(data[written:])

		written += n
		if err != nil {
			return written, err
		}

		if n == 0 {
			return written, io.ErrShortWrite
		}
	}

	return written, nil
}
