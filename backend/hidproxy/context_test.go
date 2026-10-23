package hidproxy

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

func TestWithContextIOInterruptsBlockedIO(t *testing.T) {
	conn, peer := net.Pipe()

	t.Cleanup(func() { _ = conn.Close() })
	t.Cleanup(func() { _ = peer.Close() })

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	started := make(chan struct{})

	errC := make(chan error, 1)
	go func() {
		errC <- withContextIO(ctx, conn, func() error {
			close(started)

			_, err := conn.Read(make([]byte, 1))

			return err
		})
	}()

	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("I/O operation did not start")
	}

	cancel()

	select {
	case err := <-errC:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("I/O error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("blocked I/O was not interrupted")
	}
}

func TestWithContextIOSuccessStopsCancellation(t *testing.T) {
	conn, peer := net.Pipe()

	t.Cleanup(func() { _ = conn.Close() })
	t.Cleanup(func() { _ = peer.Close() })

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	if err := withContextIO(ctx, conn, func() error { return nil }); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cancel()

	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}

	writeC := make(chan error, 1)

	go func() {
		_, err := peer.Write([]byte{1})
		writeC <- err
	}()

	buf := make([]byte, 1)

	_, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	select {
	case err := <-writeC:
		if err != nil {
			t.Fatalf("write: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("write did not complete")
	}
}
