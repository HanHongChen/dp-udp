package model

import (
	"encoding/binary"
	"time"
)

// Iperf3UDPHeader represents the iperf3 UDP packet header structure
// This matches the format used by iperf3 for UDP packets
type Iperf3UDPHeader struct {
	Sec     uint32 // timestamp seconds (network byte order)
	Usec    uint32 // timestamp microseconds (network byte order)
	SeqNum  uint64 // sequence number (unified as 64-bit for internal use)
	Is64Bit bool   // indicates if this packet uses 64-bit or 32-bit sequence numbers
}

// UDPPacket represents a complete UDP packet with iperf3 header and payload
type UDPPacket struct {
	Header  Iperf3UDPHeader
	Payload []byte
}

// NewIperf3UDPHeader creates a new iperf3 UDP header with current timestamp and sequence number
// use64Bit parameter controls whether to use 64-bit (true) or 32-bit (false) sequence numbers
func NewIperf3UDPHeader(seqNum uint64, use64Bit bool) *Iperf3UDPHeader {
	now := time.Now()
	return &Iperf3UDPHeader{
		Sec:     uint32(now.Unix()),
		Usec:    uint32(now.Nanosecond() / 1000),
		SeqNum:  seqNum,
		Is64Bit: use64Bit,
	}
}

// Marshal converts the header to network byte order bytes
func (h *Iperf3UDPHeader) Marshal() []byte {
	if h.Is64Bit {
		// 64-bit mode: sec(4) + usec(4) + seqnum(8) = 16 bytes
		buf := make([]byte, 16)
		binary.BigEndian.PutUint32(buf[0:4], h.Sec)
		binary.BigEndian.PutUint32(buf[4:8], h.Usec)
		binary.BigEndian.PutUint64(buf[8:16], h.SeqNum)
		return buf
	} else {
		// 32-bit mode: sec(4) + usec(4) + seqnum(4) = 12 bytes
		buf := make([]byte, 12)
		binary.BigEndian.PutUint32(buf[0:4], h.Sec)
		binary.BigEndian.PutUint32(buf[4:8], h.Usec)
		binary.BigEndian.PutUint32(buf[8:12], uint32(h.SeqNum))
		return buf
	}
}

// Unmarshal parses network byte order bytes into header fields
// Assumes 32-bit format by default (standard iperf3)
func (h *Iperf3UDPHeader) Unmarshal(data []byte) error {
	if len(data) < 12 {
		return ErrInvalidPacketSize
	}

	h.Sec = binary.BigEndian.Uint32(data[0:4])
	h.Usec = binary.BigEndian.Uint32(data[4:8])

	// Default to 32-bit format (standard iperf3 behavior)
	h.SeqNum = uint64(binary.BigEndian.Uint32(data[8:12]))
	h.Is64Bit = false

	return nil
}

// Unmarshal64Bit parses network byte order bytes assuming 64-bit sequence numbers
func (h *Iperf3UDPHeader) Unmarshal64Bit(data []byte) error {
	if len(data) < 16 {
		return ErrInvalidPacketSize
	}

	h.Sec = binary.BigEndian.Uint32(data[0:4])
	h.Usec = binary.BigEndian.Uint32(data[4:8])
	h.SeqNum = binary.BigEndian.Uint64(data[8:16])
	h.Is64Bit = true

	return nil
}

// GetTimestamp returns the timestamp as time.Time
func (h *Iperf3UDPHeader) GetTimestamp() time.Time {
	return time.Unix(int64(h.Sec), int64(h.Usec)*1000)
}

// NewUDPPacket creates a new UDP packet with iperf3 header
// use64Bit parameter controls the sequence number format (default: false for iperf3 compatibility)
func NewUDPPacket(seqNum uint64, payload []byte, use64Bit bool) *UDPPacket {
	return &UDPPacket{
		Header:  *NewIperf3UDPHeader(seqNum, use64Bit),
		Payload: payload,
	}
}

// NewUDPPacketDefault creates a new UDP packet with 32-bit sequence numbers (standard iperf3)
func NewUDPPacketDefault(seqNum uint64, payload []byte) *UDPPacket {
	return NewUDPPacket(seqNum, payload, false)
}

// Marshal converts the entire packet to bytes
func (p *UDPPacket) Marshal() []byte {
	headerBytes := p.Header.Marshal()
	return append(headerBytes, p.Payload...)
}

// Unmarshal parses bytes into UDP packet (assumes 32-bit format by default)
func (p *UDPPacket) Unmarshal(data []byte) error {
	if len(data) < 12 {
		return ErrInvalidPacketSize
	}

	// Default to 32-bit format
	if err := p.Header.Unmarshal(data); err != nil {
		return err
	}

	// Extract payload after 12-byte header (32-bit format)
	headerSize := 12
	if len(data) > headerSize {
		p.Payload = make([]byte, len(data)-headerSize)
		copy(p.Payload, data[headerSize:])
	}

	return nil
}

// Unmarshal64Bit parses bytes into UDP packet assuming 64-bit format
func (p *UDPPacket) Unmarshal64Bit(data []byte) error {
	if len(data) < 16 {
		return ErrInvalidPacketSize
	}

	if err := p.Header.Unmarshal64Bit(data); err != nil {
		return err
	}

	// Extract payload after 16-byte header (64-bit format)
	headerSize := 16
	if len(data) > headerSize {
		p.Payload = make([]byte, len(data)-headerSize)
		copy(p.Payload, data[headerSize:])
	}

	return nil
}
