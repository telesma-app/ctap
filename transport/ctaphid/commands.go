package ctaphid

import (
	"context"

	"github.com/telesma-app/ctap/protocol"
	"github.com/telesma-app/ctap/transport"
	ghid "github.com/telesma-app/hid"
)

func ensureDataLen(data []byte, min int) error {
	if len(data) < min {
		return ErrInvalidResponseMessage
	}

	return nil
}

func writeCBOR(ctx context.Context, dev Device, cid ChannelID, data []byte) (protocol.Command, error) {
	command := protocol.Command(data[0])

	msg, err := NewMessage(cid, CTAPHID_CBOR, data)
	if err != nil {
		return 0, err
	}

	if _, err := msg.WriteTo(ghid.WithContext(ctx, dev)); err != nil {
		return 0, err
	}

	return command, nil
}

// CBOR exchanges data, starting with a CTAP command byte, on an allocated channel.
func CBOR(ctx context.Context, dev Device, cid ChannelID, data []byte) (transport.CBORResponse, error) {
	command, err := writeCBOR(ctx, dev, cid, data)
	if err != nil {
		return transport.CBORResponse{}, err
	}

	return readCBORResponse(ctx, dev, cid, command)
}

func readCBORResponse(ctx context.Context, dev Device, cid ChannelID, command protocol.Command) (transport.CBORResponse, error) {
	bound := ghid.WithContext(ctx, dev)

	for {
		var respMsg Message
		if _, err := respMsg.ReadFrom(bound); err != nil {
			return transport.CBORResponse{}, err
		}

		if respMsg.CID() != cid {
			continue
		}

		p := respMsg[0]
		switch p.command {
		case CTAPHID_CBOR:
			if err := ensureDataLen(p.data, 1); err != nil {
				return transport.CBORResponse{}, err
			}
		case CTAPHID_ERROR:
			if err := ensureDataLen(p.data, 1); err != nil {
				return transport.CBORResponse{}, err
			}

			return transport.CBORResponse{}, &ErrorResponse{ErrorCode: Error(p.data[0])}
		case CTAPHID_KEEPALIVE:
			continue
		default:
			return transport.CBORResponse{}, ErrUnexpectedCommand
		}

		var respData []byte
		for _, p := range respMsg {
			respData = append(respData, p.data...)
		}

		response := transport.CBORResponse{
			StatusCode: transport.StatusCode(respData[0]),
			Data:       respData[1:],
		}

		return transport.ValidateCBORResponse(command, response)
	}
}

// Init initializes a CTAPHID channel.
func Init(ctx context.Context, dev Device, cid ChannelID, nonce [8]byte) (InitResponse, error) {
	msg, err := NewMessage(cid, CTAPHID_INIT, nonce[:])
	if err != nil {
		return InitResponse{}, err
	}

	bound := ghid.WithContext(ctx, dev)
	if _, err := msg.WriteTo(bound); err != nil {
		return InitResponse{}, err
	}

	for {
		var respMsg Message
		if _, err := respMsg.ReadFrom(bound); err != nil {
			return InitResponse{}, err
		}

		if respMsg.CID() != cid {
			continue
		}

		p := respMsg[0]

		switch p.command {
		case CTAPHID_INIT:
			if err := ensureDataLen(p.data, 17); err != nil {
				return InitResponse{}, err
			}

			if [8]byte(p.data[:8]) != nonce {
				// Broadcast INIT responses from other clients use the same CID.
				continue
			}

			r := InitResponse{
				Nonce:                            [8]byte(p.data[:8]),
				CID:                              ChannelID(p.data[8 : 8+4]),
				CTAPHIDProtocolVersionIdentifier: p.data[12],
				MajorDeviceVersion:               p.data[13],
				MinorDeviceVersion:               p.data[14],
				BuildDeviceVersion:               p.data[15],
				CapabilityFlags:                  p.data[16],
			}

			return r, nil
		case CTAPHID_ERROR:
			if err := ensureDataLen(p.data, 1); err != nil {
				return InitResponse{}, err
			}

			return InitResponse{}, &ErrorResponse{ErrorCode: Error(p.data[0])}
		case CTAPHID_KEEPALIVE:
			continue
		default:
			return InitResponse{}, ErrUnexpectedCommand
		}
	}
}

// Ping sends a CTAPHID ping command.
func Ping(ctx context.Context, dev Device, cid ChannelID, data []byte) (PingResponse, error) {
	msg, err := NewMessage(cid, CTAPHID_PING, data)
	if err != nil {
		return PingResponse{}, err
	}

	bound := ghid.WithContext(ctx, dev)
	if _, err := msg.WriteTo(bound); err != nil {
		return PingResponse{}, err
	}

	for {
		var respMsg Message
		if _, err := respMsg.ReadFrom(bound); err != nil {
			return PingResponse{}, err
		}

		if respMsg.CID() != cid {
			continue
		}

		p := respMsg[0]
		switch p.command {
		case CTAPHID_PING:
		case CTAPHID_ERROR:
			if err := ensureDataLen(p.data, 1); err != nil {
				return PingResponse{}, err
			}

			return PingResponse{}, &ErrorResponse{ErrorCode: Error(p.data[0])}
		case CTAPHID_KEEPALIVE:
			continue
		default:
			return PingResponse{}, ErrUnexpectedCommand
		}

		var pong []byte
		for _, p := range respMsg {
			pong = append(pong, p.data...)
		}

		return PingResponse{Bytes: pong}, nil
	}
}

// Vendor sends a CTAPHID command in 0x40-0x7f, without INIT_PACKET_BIT.
func Vendor(ctx context.Context, dev Device, cid ChannelID, command Command, data []byte) (VendorResponse, error) {
	if command < CTAPHID_VENDOR_FIRST || command > CTAPHID_VENDOR_LAST {
		return VendorResponse{}, ErrInvalidRequestMessage
	}

	msg, err := NewMessage(cid, command, data)
	if err != nil {
		return VendorResponse{}, err
	}

	bound := ghid.WithContext(ctx, dev)
	if _, err := msg.WriteTo(bound); err != nil {
		return VendorResponse{}, err
	}

	for {
		var respMsg Message
		if _, err := respMsg.ReadFrom(bound); err != nil {
			return VendorResponse{}, err
		}

		if respMsg.CID() != cid {
			continue
		}

		p := respMsg[0]
		switch p.command {
		case command:
		case CTAPHID_ERROR:
			if err := ensureDataLen(p.data, 1); err != nil {
				return VendorResponse{}, err
			}

			return VendorResponse{}, &ErrorResponse{ErrorCode: Error(p.data[0])}
		case CTAPHID_KEEPALIVE:
			continue
		default:
			return VendorResponse{}, ErrUnexpectedCommand
		}

		var response []byte
		for _, p := range respMsg {
			response = append(response, p.data...)
		}

		return VendorResponse{Data: response}, nil
	}
}

// Cancel sends a CTAPHID cancellation command.
func Cancel(ctx context.Context, dev Device, cid ChannelID) error {
	msg, err := NewMessage(cid, CTAPHID_CANCEL, nil)
	if err != nil {
		return err
	}

	if _, err := msg.WriteTo(ghid.WithContext(ctx, dev)); err != nil {
		return err
	}

	return nil
}

// Wink sends a CTAPHID wink command and waits for its response.
func Wink(ctx context.Context, dev Device, cid ChannelID) error {
	msg, err := NewMessage(cid, CTAPHID_WINK, nil)
	if err != nil {
		return err
	}

	bound := ghid.WithContext(ctx, dev)
	if _, err := msg.WriteTo(bound); err != nil {
		return err
	}

	for {
		var respMsg Message
		if _, err := respMsg.ReadFrom(bound); err != nil {
			return err
		}

		if respMsg.CID() != cid {
			continue
		}

		p := respMsg[0]

		switch p.command {
		case CTAPHID_WINK:
			return nil
		case CTAPHID_ERROR:
			if err := ensureDataLen(p.data, 1); err != nil {
				return err
			}

			return &ErrorResponse{ErrorCode: Error(p.data[0])}
		case CTAPHID_KEEPALIVE:
			continue
		default:
			return ErrUnexpectedCommand
		}
	}
}

// Lock controls the CTAPHID channel lock for up to ten seconds.
func Lock(ctx context.Context, dev Device, cid ChannelID, seconds uint8) error {
	if seconds > 10 {
		return ErrInvalidRequestMessage
	}

	msg, err := NewMessage(cid, CTAPHID_LOCK, []byte{seconds})
	if err != nil {
		return err
	}

	bound := ghid.WithContext(ctx, dev)
	if _, err := msg.WriteTo(bound); err != nil {
		return err
	}

	for {
		var respMsg Message
		if _, err := respMsg.ReadFrom(bound); err != nil {
			return err
		}

		if respMsg.CID() != cid {
			continue
		}

		p := respMsg[0]

		switch p.command {
		case CTAPHID_LOCK:
			return nil
		case CTAPHID_ERROR:
			if err := ensureDataLen(p.data, 1); err != nil {
				return err
			}

			return &ErrorResponse{ErrorCode: Error(p.data[0])}
		case CTAPHID_KEEPALIVE:
			continue
		default:
			return ErrUnexpectedCommand
		}
	}
}
