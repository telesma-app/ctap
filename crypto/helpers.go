package crypto

import (
	"bytes"
	"compress/flate"
	"fmt"
	"io"
)

const MaxLargeBlobDataSize uint = 1 << 20

func compress(uncompressed []byte) ([]byte, error) {
	buf := bytes.NewBuffer(nil)

	w, err := flate.NewWriter(buf, flate.BestCompression)
	if err != nil {
		return nil, err
	}

	defer func() {
		// to be sure we close it
		_ = w.Close()
	}()

	if _, err := w.Write(uncompressed); err != nil {
		return nil, err
	}

	if err := w.Close(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func decompress(compressed []byte) ([]byte, error) {
	r := flate.NewReader(bytes.NewReader(compressed))
	defer func() {
		_ = r.Close()
	}()

	uncompressed, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	return uncompressed, nil
}

// DecompressLargeBlobData decodes raw DEFLATE data and verifies the size
// reported by the authenticator. The limit prevents decompression bombs.
func DecompressLargeBlobData(compressed []byte, originalSize uint) ([]byte, error) {
	if originalSize > MaxLargeBlobDataSize {
		return nil, fmt.Errorf("large blob original size is too large: got %d bytes, maximum is %d", originalSize, MaxLargeBlobDataSize)
	}

	r := flate.NewReader(bytes.NewReader(compressed))
	defer func() {
		_ = r.Close()
	}()

	data, err := io.ReadAll(io.LimitReader(r, int64(originalSize)+1))
	if err != nil {
		return nil, err
	}

	if uint(len(data)) != originalSize {
		return nil, fmt.Errorf("large blob orig size mismatch: got %d, want %d", len(data), originalSize)
	}

	return data, nil
}

// CompressLargeBlobData applies the raw DEFLATE encoding required by the
// CTAP largeBlob extension.
func CompressLargeBlobData(data []byte) ([]byte, error) {
	if uint(len(data)) > MaxLargeBlobDataSize {
		return nil, fmt.Errorf("large blob data is too large: got %d bytes, maximum is %d", len(data), MaxLargeBlobDataSize)
	}

	return compress(data)
}
