package hid

import (
	"context"
	"errors"
	"testing"

	"github.com/telesma-app/ctap/transport/ctaphid"
	ghid "github.com/telesma-app/hid"
)

func TestEnumerateOpensDeviceDespiteMetadataError(t *testing.T) {
	openErr := errors.New("open failed")
	for _, test := range []struct {
		name string
		err  error
	}{
		{name: "opened"},
		{name: "open failed", err: openErr},
	} {
		t.Run(test.name, func(t *testing.T) {
			metadataErr := errors.New("metadata unavailable")
			devices := func(yield func(*ghid.DeviceInfo, error) bool) {
				if !yield(&ghid.DeviceInfo{Path: "device"}, metadataErr) {
					return
				}
				yield(&ghid.DeviceInfo{Path: "next"}, nil)
			}
			want := []*ctaphid.Transport{new(ctaphid.Transport), new(ctaphid.Transport)}
			ctx := t.Context()
			opens := 0
			open := func(gotCtx context.Context, path string) (*ctaphid.Transport, error) {
				index := opens
				opens++
				if index >= len(want) || gotCtx != ctx || path != []string{"device", "next"}[index] {
					t.Fatalf("unexpected open arguments: %v, %q", gotCtx, path)
				}
				if index == 0 && test.err != nil {
					return nil, test.err
				}
				return want[index], nil
			}

			results := 0
			for device, err := range enumerate(ctx, devices, open) {
				index := results
				results++
				if index >= len(want) {
					t.Fatal("unexpected enumeration result")
				}
				var wantErr error
				if index == 0 {
					wantErr = test.err
				}
				if err != wantErr {
					t.Fatalf("error = %v, want %v", err, wantErr)
				}
				if wantErr == nil && device != want[index] {
					t.Fatalf("device = %v, want opened transport", device)
				}
				if wantErr != nil && device != nil {
					t.Fatalf("failed open returned a device: %v", device)
				}
			}
			if opens != 2 || results != 2 {
				t.Fatalf("opens = %d, results = %d; want 2 each", opens, results)
			}
		})
	}
}

func TestEnumerateContinuesAfterDiscoveryError(t *testing.T) {
	discoveryErr := errors.New("discovery failed")
	devices := func(yield func(*ghid.DeviceInfo, error) bool) {
		if !yield(nil, discoveryErr) {
			return
		}
		yield(&ghid.DeviceInfo{Path: "available"}, nil)
	}
	want := new(ctaphid.Transport)
	opens := 0
	open := func(_ context.Context, path string) (*ctaphid.Transport, error) {
		opens++
		if path != "available" {
			t.Fatalf("unexpected path: %q", path)
		}
		return want, nil
	}

	results := 0
	for device, err := range enumerate(t.Context(), devices, open) {
		results++
		switch results {
		case 1:
			if device != nil || err != discoveryErr {
				t.Fatalf("discovery result = %v, %v", device, err)
			}
		case 2:
			if device != want || err != nil {
				t.Fatalf("device result = %v, %v", device, err)
			}
		default:
			t.Fatal("unexpected enumeration result")
		}
	}
	if opens != 1 || results != 2 {
		t.Fatalf("opens = %d, results = %d; want 1 and 2", opens, results)
	}
}

func TestEnumerateStopsWithConsumer(t *testing.T) {
	for _, withDevice := range []bool{false, true} {
		devices := func(yield func(*ghid.DeviceInfo, error) bool) {
			var info *ghid.DeviceInfo
			if withDevice {
				info = &ghid.DeviceInfo{Path: "first"}
			}
			if !yield(info, errors.New("metadata unavailable")) {
				return
			}
			t.Fatal("enumeration continued after consumer stopped")
		}
		opens := 0
		open := func(context.Context, string) (*ctaphid.Transport, error) {
			opens++
			return new(ctaphid.Transport), nil
		}

		for range enumerate(t.Context(), devices, open) {
			break
		}
		wantOpens := 0
		if withDevice {
			wantOpens = 1
		}
		if opens != wantOpens {
			t.Fatalf("opens = %d, want %d", opens, wantOpens)
		}
	}
}
