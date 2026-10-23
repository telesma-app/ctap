package ctaphid

import (
	"bytes"
)

// OutputReport is one 65-byte host-to-authenticator HID report. Byte zero is
// the report ID and the remaining bytes contain one CTAPHID packet.
type OutputReport [hidReportPacketSize]byte

// CID returns the message channel identifier.
func (m Message) CID() ChannelID {
	return m[0].cid
}

// Command returns the message command without INIT_PACKET_BIT.
func (m Message) Command() Command {
	return m[0].command
}

// DeclaredLength returns the BCNT value declared by the initial packet.
func (m Message) DeclaredLength() uint16 {
	return m[0].length
}

// Payload returns the decoded message payload.
func (m Message) Payload() []byte {
	payload := make([]byte, 0, m[0].length)
	for _, packet := range m {
		payload = append(payload, packet.data...)
	}

	return payload
}

// OutputReports encodes m as host-to-authenticator HID reports.
func (m Message) OutputReports() []OutputReport {
	reports := make([]OutputReport, len(m))
	for i, packet := range m {
		reports[i][0] = 0

		buffer := bytes.NewBuffer(reports[i][1:1])
		if _, err := packet.WriteTo(buffer); err != nil {
			panic(err)
		}
	}

	return reports
}
