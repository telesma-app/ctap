package ctapble

import (
	"bytes"
	"errors"
	"testing"
)

func TestFragmentFrameMaxLen20(t *testing.T) {
	data := make([]byte, 40)
	for i := range data {
		data[i] = byte(i)
	}

	fragments, err := fragmentFrame(PING, data, 20)
	if err != nil {
		t.Fatal(err)
	}

	want := [][]byte{
		append([]byte{0x81, 0x00, 0x28}, data[:17]...),
		append([]byte{0x00}, data[17:36]...),
		append([]byte{0x01}, data[36:]...),
	}
	if len(fragments) != len(want) {
		t.Fatalf("got %d fragments, want %d", len(fragments), len(want))
	}

	for i := range want {
		if !bytes.Equal(fragments[i], want[i]) {
			t.Errorf("fragment %d = %x, want %x", i, fragments[i], want[i])
		}
	}
}

func TestFragmentFrameMaxLen512(t *testing.T) {
	data := make([]byte, 400)

	fragments, err := fragmentFrame(PING, data, 512)
	if err != nil {
		t.Fatal(err)
	}

	if len(fragments) != 1 {
		t.Fatalf("got %d fragments, want 1", len(fragments))
	}

	if got, want := fragments[0][:3], []byte{0x81, 0x01, 0x90}; !bytes.Equal(got, want) {
		t.Fatalf("header = %x, want %x", got, want)
	}
}

func TestFragmentFrameEmptyData(t *testing.T) {
	fragments, err := fragmentFrame(CANCEL, nil, 20)
	if err != nil {
		t.Fatal(err)
	}

	if got, want := fragments[0], []byte{0xbe, 0x00, 0x00}; !bytes.Equal(got, want) {
		t.Fatalf("fragment = %x, want %x", got, want)
	}
}

func TestSequenceWrapsAfter7F(t *testing.T) {
	data := make([]byte, 17+129*19)

	fragments, err := fragmentFrame(MSG, data, 20)
	if err != nil {
		t.Fatal(err)
	}

	if got := fragments[128][0]; got != 0x7f {
		t.Fatalf("last sequence = 0x%02x, want 0x7f", got)
	}

	if got := fragments[129][0]; got != 0x00 {
		t.Fatalf("wrapped sequence = 0x%02x, want 0x00", got)
	}
}

func TestAssembleFragmentedResponseFrame(t *testing.T) {
	fragments, err := fragmentFrame(MSG, []byte("fragmented response"), 8)
	if err != nil {
		t.Fatal(err)
	}

	var (
		assembler responseFrameAssembler
		frame     *responseFrame
	)
	for _, fragment := range fragments {
		frame, err = assembler.addFragment(fragment)
		if err != nil {
			t.Fatal(err)
		}
	}

	if frame == nil || frame.status != MSG || string(frame.data) != "fragmented response" {
		t.Fatalf("frame = %#v", frame)
	}
}

func TestResponseFrameAssemblerRejectsMalformedFragments(t *testing.T) {
	tests := []struct {
		name      string
		fragments [][]byte
	}{
		{name: "empty", fragments: [][]byte{{}}},
		{name: "short initial", fragments: [][]byte{{byte(MSG), 0}}},
		{name: "oversized initial", fragments: [][]byte{{byte(MSG), 0, 1, 1, 2}}},
		{name: "orphan continuation", fragments: [][]byte{{0, 1}}},
		{name: "wrong sequence", fragments: [][]byte{{byte(MSG), 0, 2, 1}, {1, 2}}},
		{name: "interrupted", fragments: [][]byte{{byte(MSG), 0, 2, 1}, {byte(PING), 0, 0}}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var (
				assembler responseFrameAssembler
				err       error
			)
			for _, fragment := range tt.fragments {
				_, err = assembler.addFragment(fragment)
				if err != nil {
					break
				}
			}

			if !errors.Is(err, ErrInvalidFrame) {
				t.Fatalf("error = %v, want ErrInvalidFrame", err)
			}
		})
	}
}

func TestDecodeErrorCode(t *testing.T) {
	code, err := decodeErrorCode([]byte{byte(ERR_OTHER)})
	if err != nil {
		t.Fatal(err)
	}

	if code != ERR_OTHER {
		t.Fatalf("code = 0x%x", code)
	}
}
