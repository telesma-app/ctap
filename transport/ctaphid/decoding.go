package ctaphid

import (
	"encoding/binary"
	"io"
)

func (m *Message) ReadFrom(device io.Reader) (int64, error) {
	var (
		bytesRead        int
		expectedCID      ChannelID
		expectedSequence byte
	)

	total := -1
	for total != 0 {
		rawPacket := make([]byte, hidPacketSize)

		n, err := io.ReadFull(device, rawPacket)
		if err != nil {
			return 0, err
		}

		bytesRead += n

		var p packet

		copy(p.cid[:], rawPacket[:4])

		cmdOrSeq := rawPacket[4]

		if (cmdOrSeq & INIT_PACKET_BIT) != 0 {
			if total >= 0 {
				return 0, ErrInvalidResponseMessage
			}

			p.command = Command(cmdOrSeq & ^INIT_PACKET_BIT)
			p.length = binary.BigEndian.Uint16(rawPacket[5:7])
			total = int(p.length)
			expectedCID = p.cid
			expectedSequence = 0

			dataCnt := total
			if dataCnt > initPacketDataSize {
				dataCnt = initPacketDataSize
			}

			p.data = append([]byte(nil), rawPacket[initPacketHeaderSize:initPacketHeaderSize+dataCnt]...)
			total -= dataCnt
		} else {
			if total < 0 {
				return 0, ErrInvalidResponseMessage
			}

			if p.cid != expectedCID || cmdOrSeq != expectedSequence {
				return 0, ErrInvalidResponseMessage
			}

			p.sequence = cmdOrSeq
			p.continuation = true

			dataCnt := total
			if dataCnt > continuationPacketDataSize {
				dataCnt = continuationPacketDataSize
			}

			p.data = append([]byte(nil), rawPacket[continuationPacketHeaderSize:continuationPacketHeaderSize+dataCnt]...)
			total -= dataCnt
			expectedSequence++
		}

		*m = append(*m, &p)
	}

	return int64(bytesRead), nil
}
