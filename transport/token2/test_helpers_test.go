package token2

import (
	"testing"
	"time"
)

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
