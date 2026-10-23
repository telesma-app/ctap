package ctaphid

import (
	"context"
	"errors"
	"io"
	"sync"

	ctaptransport "github.com/telesma-app/ctap/transport"
	ghid "github.com/telesma-app/hid"
)

// channelDevice continuously drains input reports from a shared HID endpoint
// and retains only reports addressed to one allocated CTAPHID channel. Other
// applications receive their own channels, but their reports are delivered to
// every open host handle on some platforms and must not fill its input queue.
type channelDevice struct {
	device Device

	ctx    context.Context
	cancel context.CancelCauseFunc

	mu      sync.Mutex
	cid     ChannelID
	pending [][]byte
	readErr error

	wake    chan struct{}
	stopped chan struct{}

	closeOnce sync.Once
	closeErr  error
}

func newChannelDevice(device Device, cid ChannelID) *channelDevice {
	ctx, cancel := context.WithCancelCause(context.Background())
	d := &channelDevice{
		device:  ioDevice{Device: device},
		cid:     cid,
		ctx:     ctx,
		cancel:  cancel,
		wake:    make(chan struct{}, 1),
		stopped: make(chan struct{}),
	}

	go d.readReports()

	return d
}

func (d *channelDevice) Read(ctx context.Context, p []byte) (int, error) {
	for {
		report, err := d.nextReport()
		if report != nil {
			return copy(p, report), nil
		}

		if err != nil {
			return 0, err
		}

		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-d.wake:
		}
	}
}

func (d *channelDevice) Write(ctx context.Context, p []byte) (int, error) {
	return d.device.Write(ctx, p)
}

func (d *channelDevice) Close() error {
	d.closeOnce.Do(func() {
		// Cancel the contextual reader before waiting for it.  On Linux, closing a
		// file descriptor from another goroutine does not reliably interrupt a
		// read that is already blocked in the kernel.
		d.cancel(io.ErrClosedPipe)
		d.closeErr = d.device.Close()
		<-d.stopped
	})

	return d.closeErr
}

func (d *channelDevice) setCID(cid ChannelID) {
	d.mu.Lock()
	d.cid = cid
	d.pending = nil
	d.mu.Unlock()
}

func (d *channelDevice) stop() {
	d.cancel(context.Canceled)
	<-d.stopped
}

func (d *channelDevice) readReports() {
	defer close(d.stopped)

	reader := ghid.WithContext(d.ctx, d.device)

	for {
		report := make([]byte, hidPacketSize)
		if _, err := io.ReadFull(reader, report); err != nil {
			d.finish(err)
			return
		}

		if d.enqueue(report) {
			d.notify()
		}
	}
}

func (d *channelDevice) nextReport() ([]byte, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if len(d.pending) == 0 {
		return nil, d.readErr
	}

	report := d.pending[0]
	d.pending[0] = nil

	d.pending = d.pending[1:]
	if len(d.pending) == 0 {
		d.pending = nil
	}

	return report, nil
}

func (d *channelDevice) enqueue(report []byte) bool {
	var cid ChannelID
	copy(cid[:], report)

	d.mu.Lock()
	defer d.mu.Unlock()

	if cid != d.cid {
		return false
	}

	d.pending = append(d.pending, report)

	return true
}

func (d *channelDevice) finish(err error) {
	// ghid.WithContext reports ctx.Err(), which does not retain a cancellation
	// cause. Restore the explicit Close cause at the channel boundary.
	if errors.Is(err, context.Canceled) && errors.Is(context.Cause(d.ctx), io.ErrClosedPipe) {
		err = &ctaptransport.IOError{
			Operation: ctaptransport.IORead,
			Err:       io.ErrClosedPipe,
		}
	}

	d.mu.Lock()
	d.readErr = err
	d.mu.Unlock()
	d.notify()
}

func (d *channelDevice) notify() {
	select {
	case d.wake <- struct{}{}:
	default:
	}
}
