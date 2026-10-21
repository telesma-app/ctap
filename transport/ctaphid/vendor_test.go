package ctaphid_test

import (
	"context"
	"errors"
	"testing"

	"github.com/telesma-app/ctap/internal/testhid"
	"github.com/telesma-app/ctap/transport/ctaphid"
)

func TestVendorRejectsNonVendorCommand(t *testing.T) {
	_, err := ctaphid.Vendor(context.Background(), testhid.New(t), ctaphid.ChannelID{}, ctaphid.CTAPHID_PING, nil)
	if err, target := err, ctaphid.ErrInvalidRequestMessage; !errors.Is(err, target) {
		t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
	}
}

func TestVendorReturnsCTAPHIDError(t *testing.T) {
	cid := ctaphid.ChannelID{1, 2, 3, 4}
	fake := testhid.New(t, testhid.CTAPHIDError(cid, ctaphid.ERR_INVALID_CMD))
	_, err := ctaphid.Vendor(context.Background(), fake, cid, ctaphid.CTAPHID_VENDOR_FIRST, nil)
	if err == nil {
		t.Fatalf("expected an error")
	}

	var response *ctaphid.ErrorResponse
	if err := err; !errors.As(err, &response) {
		t.Fatalf("error %v does not match requested type", err)
	}
	if got, want := response.ErrorCode, ctaphid.ERR_INVALID_CMD; got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}
	{
		err, want := err, ctaphid.ERR_INVALID_CMD.String()
		if err == nil || err.Error() != want {
			t.Errorf("got error %v, want %q", err, want)
		}
	}
}
