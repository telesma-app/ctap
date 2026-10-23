package ctaphid

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	ctaptransport "github.com/telesma-app/ctap/transport"
)

func TestChannelDeviceFiltersReports(t *testing.T) {
	cid := ChannelID{1, 2, 3, 4}
	dev := newMultiplexedDevice(cid)
	channel := newChannelDevice(dev, cid)

	t.Cleanup(func() {
		if err := channel.Close(); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	foreignReport := rawResponseReport(
		ChannelID{5, 6, 7, 8},
		CTAPHID_CBOR,
		[]byte{byte(ctaptransport.CTAP2_OK)},
	)

	drained := make(chan struct{})
	go func() {
		defer close(drained)

		for range 64 {
			dev.reads <- bytes.Clone(foreignReport)
		}
	}()

	receive(t, drained, "foreign reports were not drained")

	want := rawResponseReport(cid, CTAPHID_CBOR, []byte{byte(ctaptransport.CTAP2_OK)})
	dev.reads <- want

	if got, want := readChannelReport(t, channel), want; (got == nil) != (want == nil) || !bytes.Equal(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestChannelDeviceSwitchesCID(t *testing.T) {
	dev := newMultiplexedDevice(ChannelID{1, 2, 3, 4})
	channel := newChannelDevice(dev, BROADCAST_CID)

	t.Cleanup(func() {
		if err := channel.Close(); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	broadcast := rawResponseReport(BROADCAST_CID, CTAPHID_INIT, nil)
	if got := channel.enqueue(broadcast); !got {
		t.Fatalf("got false, want true")
	}

	allocatedCID := ChannelID{9, 8, 7, 6}
	channel.setCID(allocatedCID)

	report, err := channel.nextReport()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := report; got != nil {
		t.Errorf("got %#v, want nil; context: %s", got, "reports queued for the previous CID must be discarded")
	}

	if got := channel.enqueue(broadcast); got {
		t.Errorf("got true, want false")
	}

	allocated := rawResponseReport(allocatedCID, CTAPHID_CBOR, nil)
	if got := channel.enqueue(allocated); !got {
		t.Fatalf("got false, want true")
	}

	report, err = channel.nextReport()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got, want := report, allocated; (got == nil) != (want == nil) || !bytes.Equal(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestChannelDeviceReadsReportInParts(t *testing.T) {
	cid := ChannelID{1, 2, 3, 4}
	dev := newMultiplexedDevice(cid)
	channel := newChannelDevice(dev, cid)

	t.Cleanup(func() {
		if err := channel.Close(); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	want := rawResponseReport(cid, CTAPHID_CBOR, []byte{byte(ctaptransport.CTAP2_OK)})
	dev.reads <- bytes.Clone(want[:17])

	dev.reads <- bytes.Clone(want[17:])

	if got, want := readChannelReport(t, channel), want; (got == nil) != (want == nil) || !bytes.Equal(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestChannelDeviceStopLeavesDeviceOpen(t *testing.T) {
	dev := newMultiplexedDevice(ChannelID{1, 2, 3, 4})
	channel := newChannelDevice(dev, BROADCAST_CID)

	stopped := make(chan struct{})

	go func() {
		channel.stop()
		close(stopped)
	}()

	receive(t, stopped, "channel reader did not stop")

	select {
	case <-dev.closed:
		t.Fatal("stop closed the underlying device")
	default:
	}

	_, err := channel.nextReport()
	if err, target := err, context.Canceled; !errors.Is(err, target) {
		t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
	}

	if err, target := err, io.ErrClosedPipe; errors.Is(err, target) {
		t.Fatalf("got error %v, unexpectedly matches %#v", err, target)
	}

	if err := dev.Close(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestChannelDeviceCloseCancelsReaderBeforeWaiting(t *testing.T) {
	dev := newCancelOnlyDevice()
	channel := newChannelDevice(dev, BROADCAST_CID)
	receive(t, dev.readStarted, "channel reader did not start")

	closed := make(chan error, 1)
	go func() {
		closed <- channel.Close()
	}()

	if err := receive(t, closed, "Close did not cancel the channel reader"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	select {
	case <-dev.closed:
	default:
		t.Fatal("Close did not close the underlying device")
	}

	_, err := channel.nextReport()
	if err, target := err, io.ErrClosedPipe; !errors.Is(err, target) {
		t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
	}

	var readErr *ctaptransport.IOError
	if err := err; !errors.As(err, &readErr) {
		t.Fatalf("error %v does not match requested type", err)
	}

	if got, want := readErr.Operation, ctaptransport.IORead; got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func readChannelReport(t *testing.T, channel *channelDevice) []byte {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()

	report := make([]byte, hidPacketSize)

	n, err := channel.Read(ctx, report)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got, want := n, hidPacketSize; got != want {
		t.Fatalf("got %#v, want %#v", got, want)
	}

	return report
}

type multiplexedDevice struct {
	reads     chan []byte
	closed    chan struct{}
	closeOnce sync.Once
	cid       ChannelID
}

type cancelOnlyDevice struct {
	readStarted chan struct{}
	closed      chan struct{}
	startOnce   sync.Once
	closeOnce   sync.Once
}

func newCancelOnlyDevice() *cancelOnlyDevice {
	return &cancelOnlyDevice{
		readStarted: make(chan struct{}),
		closed:      make(chan struct{}),
	}
}

func (d *cancelOnlyDevice) Read(ctx context.Context, _ []byte) (int, error) {
	d.startOnce.Do(func() {
		close(d.readStarted)
	})
	<-ctx.Done()

	return 0, ctx.Err()
}

func (d *cancelOnlyDevice) Write(ctx context.Context, p []byte) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}

	return len(p), nil
}

func (d *cancelOnlyDevice) Close() error {
	d.closeOnce.Do(func() {
		close(d.closed)
	})

	return nil
}

func newMultiplexedDevice(cid ChannelID) *multiplexedDevice {
	return &multiplexedDevice{
		reads:  make(chan []byte, 1),
		closed: make(chan struct{}),
		cid:    cid,
	}
}

func (d *multiplexedDevice) Read(ctx context.Context, p []byte) (int, error) {
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case <-d.closed:
		return 0, io.ErrClosedPipe
	case report := <-d.reads:
		return copy(p, report), nil
	}
}

func (d *multiplexedDevice) Write(ctx context.Context, p []byte) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}

	switch p[5] {
	case byte(CTAPHID_INIT) | INIT_PACKET_BIT:
		data := append(bytes.Clone(p[8:16]), d.cid[:]...)

		data = append(data, 2, 1, 0, 0, byte(CAPABILITY_CBOR))
		d.reads <- rawResponseReport(BROADCAST_CID, CTAPHID_INIT, data)
	case byte(CTAPHID_CBOR) | INIT_PACKET_BIT:
		d.reads <- rawResponseReport(d.cid, CTAPHID_CBOR, []byte{byte(ctaptransport.CTAP2_OK)})
	}

	return len(p), nil
}

func (d *multiplexedDevice) Close() error {
	d.closeOnce.Do(func() {
		close(d.closed)
	})

	return nil
}

func rawResponseReport(cid ChannelID, command Command, data []byte) []byte {
	report := make([]byte, hidPacketSize)
	copy(report, cid[:])
	report[4] = byte(command) | INIT_PACKET_BIT
	binary.BigEndian.PutUint16(report[5:7], uint16(len(data)))
	copy(report[7:], data)

	return report
}
