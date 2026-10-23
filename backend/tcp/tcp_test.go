package tcp

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func TestDeviceReadAssemblesFragmentedReport(t *testing.T) {
	conn, peer := net.Pipe()
	device := &Device{conn: conn}

	t.Cleanup(func() { _ = device.Close() })
	t.Cleanup(func() { _ = peer.Close() })

	want := make([]byte, inputReportSize)

	for i := range want {
		want[i] = byte(i)
	}
	go func() {
		_, _ = peer.Write(want[:17])
		_, _ = peer.Write(want[17:])
	}()

	got := make([]byte, inputReportSize)

	n, err := runIO(t, func() (int, error) {
		return device.Read(t.Context(), got)
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got, want := n, inputReportSize; got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}

	if got, want := got, want; (got == nil) != (want == nil) || !bytes.Equal(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestDeviceWriteStripsReportID(t *testing.T) {
	conn, peer := net.Pipe()
	device := &Device{conn: conn}

	t.Cleanup(func() { _ = device.Close() })
	t.Cleanup(func() { _ = peer.Close() })

	report := make([]byte, outputReportSize)
	for i := 1; i < len(report); i++ {
		report[i] = byte(i)
	}

	got := make(chan []byte, 1)
	go func() {
		data := make([]byte, inputReportSize)

		_, _ = io.ReadFull(peer, data)
		got <- data
	}()

	n, err := runIO(t, func() (int, error) {
		return device.Write(t.Context(), report)
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got, want := n, outputReportSize; got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}

	if got, want := receive(t, got, "peer did not read the report"), report[1:]; (got == nil) != (want == nil) || !bytes.Equal(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestDeviceRejectsInvalidReportShapes(t *testing.T) {
	conn, peer := net.Pipe()
	device := &Device{conn: conn}

	t.Cleanup(func() { _ = device.Close() })
	t.Cleanup(func() { _ = peer.Close() })

	for _, size := range []int{0, inputReportSize - 1, inputReportSize + 1} {
		n, err := runIO(t, func() (int, error) {
			return device.Read(t.Context(), make([]byte, size))
		})
		if n != 0 {
			t.Errorf("Read returned %d bytes, want 0", n)
		}

		if err == nil {
			t.Errorf("expected an error")
		}
	}

	for _, size := range []int{0, outputReportSize - 1, outputReportSize + 1} {
		n, err := runIO(t, func() (int, error) {
			return device.Write(t.Context(), make([]byte, size))
		})
		if n != 0 {
			t.Errorf("Write returned %d bytes, want 0", n)
		}

		if err == nil {
			t.Errorf("expected an error")
		}
	}

	report := make([]byte, outputReportSize)
	report[0] = 1

	n, err := runIO(t, func() (int, error) {
		return device.Write(t.Context(), report)
	})
	if n != 0 {
		t.Errorf("Write returned %d bytes, want 0", n)
	}

	if err == nil {
		t.Errorf("expected an error")
	}
}

func TestDeviceReadReportsShortInput(t *testing.T) {
	conn, peer := net.Pipe()
	device := &Device{conn: conn}

	t.Cleanup(func() { _ = device.Close() })
	t.Cleanup(func() { _ = peer.Close() })

	go func() {
		_, _ = peer.Write(make([]byte, inputReportSize-1))
		_ = peer.Close()
	}()

	n, err := runIO(t, func() (int, error) {
		return device.Read(t.Context(), make([]byte, inputReportSize))
	})
	if got, want := n, inputReportSize-1; got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}

	if err, target := err, io.ErrUnexpectedEOF; !errors.Is(err, target) {
		t.Errorf("got error %v, want errors.Is(error, %#v)", err, target)
	}
}

func TestDeviceReadCancellationLeavesConnectionReusable(t *testing.T) {
	conn, peer := net.Pipe()
	device := &Device{conn: conn}

	t.Cleanup(func() { _ = device.Close() })
	t.Cleanup(func() { _ = peer.Close() })

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	n, err := runIO(t, func() (int, error) {
		return device.Read(ctx, make([]byte, inputReportSize))
	})
	if n != 0 {
		t.Errorf("Read returned %d bytes, want 0", n)
	}

	if err, target := err, context.Canceled; !errors.Is(err, target) {
		t.Errorf("got error %v, want errors.Is(error, %#v)", err, target)
	}

	want := bytes.Repeat([]byte{0x5a}, inputReportSize)
	go func() { _, _ = peer.Write(want) }()

	got := make([]byte, inputReportSize)

	n, err = runIO(t, func() (int, error) {
		return device.Read(t.Context(), got)
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got, want := n, inputReportSize; got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}

	if got, want := got, want; (got == nil) != (want == nil) || !bytes.Equal(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestDeviceReadCancellationInterruptsBlockedRead(t *testing.T) {
	conn, peer := net.Pipe()
	device := &Device{conn: conn}

	t.Cleanup(func() { _ = device.Close() })
	t.Cleanup(func() { _ = peer.Close() })

	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	t.Cleanup(cancel)

	n, err := runIO(t, func() (int, error) {
		return device.Read(ctx, make([]byte, inputReportSize))
	})
	if n != 0 {
		t.Errorf("Read returned %d bytes, want 0", n)
	}

	if err, target := err, context.DeadlineExceeded; !errors.Is(err, target) {
		t.Errorf("got error %v, want errors.Is(error, %#v)", err, target)
	}
}

func TestDeviceWriteCancellationLeavesConnectionReusable(t *testing.T) {
	conn, peer := net.Pipe()
	device := &Device{conn: conn}

	t.Cleanup(func() { _ = device.Close() })
	t.Cleanup(func() { _ = peer.Close() })

	report := make([]byte, outputReportSize)

	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	t.Cleanup(cancel)

	_, err := runIO(t, func() (int, error) {
		return device.Write(ctx, report)
	})
	if err, target := err, context.DeadlineExceeded; !errors.Is(err, target) {
		t.Errorf("got error %v, want errors.Is(error, %#v)", err, target)
	}

	readDone := make(chan error, 1)
	go func() {
		data := make([]byte, inputReportSize)

		_, err := io.ReadFull(peer, data)
		readDone <- err
	}()

	n, err := runIO(t, func() (int, error) {
		return device.Write(t.Context(), report)
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got, want := n, outputReportSize; got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}

	if err := receive(t, readDone, "peer did not finish reading the report"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDeviceWriteReportsConnectionFailure(t *testing.T) {
	conn, peer := net.Pipe()
	device := &Device{conn: conn}

	t.Cleanup(func() { _ = device.Close() })

	if err := peer.Close(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err := runIO(t, func() (int, error) {
		return device.Write(t.Context(), make([]byte, outputReportSize))
	})
	if err == nil {
		t.Errorf("expected an error")
	}
}

func TestDeviceCloseInterruptsBlockedRead(t *testing.T) {
	conn, peer := net.Pipe()
	device := &Device{conn: conn}

	t.Cleanup(func() { _ = device.Close() })
	t.Cleanup(func() { _ = peer.Close() })

	done := make(chan error, 1)
	go func() {
		_, err := device.Read(t.Context(), make([]byte, inputReportSize))
		done <- err
	}()

	if err := device.Close(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if err := receive(t, done, "Close did not interrupt the read"); err == nil {
		t.Errorf("expected an error")
	}
}

func TestOpenAllocatesCTAPHIDChannel(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	serverDone := make(chan struct{})

	t.Cleanup(func() { receive(t, serverDone, "TCP server did not stop") })
	t.Cleanup(func() { _ = listener.Close() })

	serverErr := make(chan error, 1)

	go func() {
		defer close(serverDone)

		conn, err := listener.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer func() { _ = conn.Close() }()

		if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
			serverErr <- err
			return
		}

		request := make([]byte, inputReportSize)
		if _, err := io.ReadFull(conn, request); err != nil {
			serverErr <- err
			return
		}

		if !bytes.Equal(request[:4], []byte{0xff, 0xff, 0xff, 0xff}) || request[4] != 0x86 {
			serverErr <- errors.New("unexpected CTAPHID_INIT request")
			return
		}

		response := make([]byte, inputReportSize)
		copy(response[:4], request[:4])
		response[4] = 0x86
		binary.BigEndian.PutUint16(response[5:7], 17)
		copy(response[7:15], request[7:15])
		copy(response[15:19], []byte{1, 2, 3, 4})
		copy(response[19:24], []byte{2, 1, 0, 0, 0x04})

		if _, err := conn.Write(response[:11]); err != nil {
			serverErr <- err
			return
		}

		_, err = conn.Write(response[11:])
		serverErr <- err
	}()

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	opened := make(chan error, 1)

	go func() {
		transport, err := Open(ctx, listener.Addr().String())
		if err != nil {
			opened <- err
			return
		}

		opened <- transport.Close()
	}()

	if err := receive(t, opened, "Open or Close did not complete"); err != nil {
		t.Fatal(err)
	}

	if err := receive(t, serverErr, "TCP server did not complete the exchange"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func runIO(t testing.TB, operation func() (int, error)) (int, error) {
	t.Helper()

	type result struct {
		n   int
		err error
	}

	done := make(chan result, 1)

	go func() {
		n, err := operation()
		done <- result{n: n, err: err}
	}()

	got := receive(t, done, "device I/O did not complete")

	return got.n, got.err
}

func receive[T any](t testing.TB, ch <-chan T, message string) T {
	t.Helper()

	select {
	case value := <-ch:
		return value
	case <-time.After(time.Second):
		t.Fatal(message)

		var zero T

		return zero
	}
}
