package ctapble

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	initializationFragmentHeaderLength = 3
	continuationFragmentHeaderLength   = 1
	maximumFrameDataLength             = 0xffff
	initializationFragmentBit          = 0x80
	maximumSequence                    = 0x7f
)

type responseFrame struct {
	status Command
	data   []byte
}

func fragmentFrame(commandOrStatus Command, data []byte, maxLen int) ([][]byte, error) {
	if len(data) > maximumFrameDataLength {
		return nil, ErrDataTooLarge
	}

	initializationDataLength := min(len(data), maxLen-initializationFragmentHeaderLength)
	initializationFragment := make([]byte, initializationFragmentHeaderLength+initializationDataLength)
	initializationFragment[0] = byte(commandOrStatus)
	binary.BigEndian.PutUint16(initializationFragment[1:initializationFragmentHeaderLength], uint16(len(data)))
	copy(initializationFragment[initializationFragmentHeaderLength:], data[:initializationDataLength])
	fragments := [][]byte{initializationFragment}

	data = data[initializationDataLength:]
	for sequence := byte(0); len(data) != 0; sequence = (sequence + 1) & maximumSequence {
		fragmentDataLength := min(len(data), maxLen-continuationFragmentHeaderLength)
		fragment := make([]byte, continuationFragmentHeaderLength+fragmentDataLength)
		fragment[0] = sequence
		copy(fragment[continuationFragmentHeaderLength:], data[:fragmentDataLength])
		fragments = append(fragments, fragment)
		data = data[fragmentDataLength:]
	}

	return fragments, nil
}

type responseFrameAssembler struct {
	status     Command
	dataLength int
	data       []byte
	sequence   byte
	assembling bool
}

func (a *responseFrameAssembler) addFragment(fragment []byte) (*responseFrame, error) {
	if len(fragment) == 0 {
		return nil, errors.Join(ErrInvalidFrame, errors.New("empty fragment"))
	}

	if fragment[0]&initializationFragmentBit != 0 {
		return a.initializationFragment(fragment)
	}

	return a.continuationFragment(fragment)
}

func (a *responseFrameAssembler) initializationFragment(fragment []byte) (*responseFrame, error) {
	if a.assembling {
		return nil, errors.Join(ErrInvalidFrame, errors.New("initialization fragment interrupted frame"))
	}

	if len(fragment) < initializationFragmentHeaderLength {
		return nil, errors.Join(ErrInvalidFrame, errors.New("short initialization fragment"))
	}

	a.status = Command(fragment[0])

	a.dataLength = int(binary.BigEndian.Uint16(fragment[1:initializationFragmentHeaderLength]))
	if len(fragment)-initializationFragmentHeaderLength > a.dataLength {
		return nil, errors.Join(ErrInvalidFrame, errors.New("initialization fragment exceeds declared data length"))
	}

	a.data = fragment[initializationFragmentHeaderLength:]
	a.sequence = 0

	a.assembling = len(a.data) != a.dataLength
	if a.assembling {
		return nil, nil
	}

	return a.completeFrame(), nil
}

func (a *responseFrameAssembler) continuationFragment(fragment []byte) (*responseFrame, error) {
	if !a.assembling {
		return nil, errors.Join(ErrInvalidFrame, errors.New("continuation fragment without initialization fragment"))
	}

	if fragment[0] != a.sequence {
		return nil, fmt.Errorf("%w: sequence 0x%02x, want 0x%02x", ErrInvalidFrame, fragment[0], a.sequence)
	}

	if len(a.data)+len(fragment)-continuationFragmentHeaderLength > a.dataLength {
		return nil, errors.Join(ErrInvalidFrame, errors.New("continuation fragment exceeds declared data length"))
	}

	a.data = append(a.data, fragment[continuationFragmentHeaderLength:]...)

	a.sequence = (a.sequence + 1) & maximumSequence
	if len(a.data) != a.dataLength {
		return nil, nil
	}

	a.assembling = false

	return a.completeFrame(), nil
}

func (a *responseFrameAssembler) completeFrame() *responseFrame {
	result := &responseFrame{status: a.status, data: a.data}
	a.data = nil

	return result
}

func decodeErrorCode(data []byte) (ErrorCode, error) {
	if len(data) != 1 {
		return 0, errors.Join(ErrInvalidFrame, errors.New("invalid encapsulation error length"))
	}

	return ErrorCode(data[0]), nil
}
