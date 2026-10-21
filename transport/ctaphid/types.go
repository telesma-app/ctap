package ctaphid

// Message is a sequence of packets.
type Message []*packet

const (
	hidPacketSize                = 64
	hidReportPacketSize          = hidPacketSize + 1
	initPacketHeaderSize         = 7
	continuationPacketHeaderSize = 5
	initPacketDataSize           = hidPacketSize - initPacketHeaderSize
	continuationPacketDataSize   = hidPacketSize - continuationPacketHeaderSize
)

type packet struct {
	cid          ChannelID
	command      Command
	sequence     byte
	length       uint16
	data         []byte
	continuation bool
}

// ChannelID identifies a CTAPHID channel.
type ChannelID [4]byte

// BROADCAST_CID is the channel used for allocation.
var BROADCAST_CID = ChannelID{0xff, 0xff, 0xff, 0xff}

// InitResponse is a CTAPHID_INIT response.
type InitResponse struct {
	Nonce                            [8]byte
	CID                              ChannelID
	CTAPHIDProtocolVersionIdentifier byte
	MajorDeviceVersion               byte
	MinorDeviceVersion               byte
	BuildDeviceVersion               byte
	CapabilityFlags                  byte
}

func (r *InitResponse) ImplementsWink() bool {
	return r.CapabilityFlags&byte(CAPABILITY_WINK) != 0
}

func (r *InitResponse) ImplementsLock() bool {
	return r.CapabilityFlags&byte(CAPABILITY_LOCK) != 0
}

func (r *InitResponse) ImplementsCBOR() bool {
	return r.CapabilityFlags&byte(CAPABILITY_CBOR) != 0
}

func (r *InitResponse) NotImplementsMSG() bool {
	return r.CapabilityFlags&byte(CAPABILITY_NMSG) != 0
}

// PingResponse contains the CTAPHID_PING echo.
type PingResponse struct {
	Bytes []byte
}

// ErrorResponse represents CTAPHID_ERROR (0x3F) command response.
type ErrorResponse struct {
	ErrorCode Error
}

// Error returns the symbolic name of ErrorCode.
func (r *ErrorResponse) Error() string {
	return r.ErrorCode.String()
}

// VendorResponse contains a vendor command's opaque payload.
type VendorResponse struct {
	Data []byte
}
