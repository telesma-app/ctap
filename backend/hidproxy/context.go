package hidproxy

import (
	"context"
	"io"
)

// withContextIO makes a blocking operation on a fresh proxy connection obey
// ctx. A canceled connection is not returned to the caller, so closing it is
// enough to interrupt pending I/O without managing connection deadlines.
func withContextIO(ctx context.Context, conn io.Closer, operation func() error) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		_ = conn.Close()

		close(done)
	})

	err := operation()
	if stop() {
		return err
	}

	<-done

	return ctx.Err()
}
