package ble

import (
	"context"
	"errors"
	"iter"
	"sync"
	"testing"
	"time"

	gble "github.com/telesma-app/ble"
	ctaptransport "github.com/telesma-app/ctap/transport"
)

type closeTrackingPeripheral struct {
	closed bool
}

func (*closeTrackingPeripheral) DiscoverServices(context.Context, ...gble.UUID) ([]gble.Service, error) {
	return nil, nil
}
func (p *closeTrackingPeripheral) Close() error {
	p.closed = true
	return nil
}

func TestOpenClosesPeripheralAfterInitializationError(t *testing.T) {
	peripheral := &closeTrackingPeripheral{}

	_, err := openWith(context.Background(), "device", func(context.Context, gble.Identifier) (gble.Peripheral, error) {
		return peripheral, nil
	})
	if err == nil {
		t.Fatal("Open succeeded")
	}

	if !peripheral.closed {
		t.Fatal("peripheral was not closed")
	}
}

type fakeDevice struct {
	id     gble.Identifier
	closed bool
}

func (*fakeDevice) CBOR(context.Context, []byte) (ctaptransport.CBORResponse, error) {
	return ctaptransport.CBORResponse{}, nil
}
func (d *fakeDevice) Close() error {
	d.closed = true
	return nil
}

func TestEnumeratorDeduplicatesAndEndsScanWindowWithoutError(t *testing.T) {
	devices := func(ctx context.Context) iter.Seq2[*gble.DeviceInfo, error] {
		return func(yield func(*gble.DeviceInfo, error) bool) {
			for _, id := range []gble.Identifier{"first", "first", "second"} {
				if !yield(&gble.DeviceInfo{ID: id}, nil) {
					return
				}
			}

			<-ctx.Done()
			yield(nil, ctx.Err())
		}
	}

	var (
		mu     sync.Mutex
		opened []gble.Identifier
	)

	open := func(_ context.Context, id gble.Identifier) (ctaptransport.Device, error) {
		mu.Lock()

		opened = append(opened, id)
		mu.Unlock()

		return &fakeDevice{id: id}, nil
	}

	var got []gble.Identifier

	for device, err := range enumerator(time.Millisecond, devices, open)(context.Background()) {
		if err != nil {
			t.Fatal(err)
		}

		got = append(got, device.(*fakeDevice).id)
	}

	if len(got) != 2 || got[0] != "first" || got[1] != "second" {
		t.Fatalf("devices = %q", got)
	}

	if len(opened) != 2 {
		t.Fatalf("opened = %q", opened)
	}
}

func TestEnumeratorPropagatesParentCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	devices := func(context.Context) iter.Seq2[*gble.DeviceInfo, error] {
		return func(func(*gble.DeviceInfo, error) bool) {}
	}
	open := func(context.Context, gble.Identifier) (ctaptransport.Device, error) {
		t.Fatal("open called")
		return nil, nil
	}

	var got error
	for _, err := range enumerator(time.Second, devices, open)(ctx) {
		got = err
	}

	if !errors.Is(got, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", got)
	}
}
