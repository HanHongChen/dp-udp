package util

import "fmt"

func AnalyzePacket(ipPacket []byte) (bool, bool, uint64, error) {
	// fmt.Printf("=== PACKET STRUCTURE ANALYSIS ===\n")
	// fmt.Printf("Total packet length: %d bytes\n", len(ipPacket))

	// Basic IP header validation
	if len(ipPacket) < 20 {
		return false, false, 0, fmt.Errorf("packet too short for IP header")
	}

	// fmt.Printf("Version: %02x, Len: %02x, Protocol(UDP 0x11, TCP 0x06, ICMP 0x01):  %02x\n",
	// 	(ipPacket[0] >> 4), (ipPacket[0] & 0x0F), ipPacket[9])

	// Check if it's IPv4
	if (ipPacket[0] >> 4) != 4 {
		return false, false, 0, fmt.Errorf("not an IPv4 packet")
	}

	protocol := ipPacket[9]

	// 檢查協議類型
	switch protocol {
	case 6: // TCP
		// fmt.Printf("TCP packet detected - control message, should skip\n")
		return true, false, 0, nil

	case 1: // ICMP
		return false, false, 0, fmt.Errorf("ICMP control packet detected - not relevant\n")

	case 2: // IGMP
		return false, false, 0, fmt.Errorf("IGMP control packet detected - not relevant\n")

	case 17: // UDP
		// fmt.Printf("UDP packet detected - analyzing content\n")

	default:
		return false, false, 0, fmt.Errorf("unknown protocol %d detected - not relevant\n", protocol)
	}

	ihl := int(ipPacket[0]&0x0F) * 4
	udpPayloadStart := ihl + 8

	// 檢查 UDP header 長度
	if len(ipPacket) < udpPayloadStart {
		return false, false, 0, fmt.Errorf("UDP packet too short for UDP header\n")
	}

	// 檢查是否有足夠長度包含 iperf3 header
	if len(ipPacket) < udpPayloadStart+12 {
		return false, true, 0, nil // UDP 封包，但沒有 iperf3 header，不套用 packet elimination
	}

	// 提取 iperf3 序號
	udpPayload := ipPacket[udpPayloadStart:]

	// Extract iperf3 sequence number (32-bit, big-endian, at offset 8)
	seqNum := uint64(udpPayload[8])<<24 |
		uint64(udpPayload[9])<<16 |
		uint64(udpPayload[10])<<8 |
		uint64(udpPayload[11])

	return false, false, seqNum, nil // UDP 封包且有 iperf3 header，套用 packet elimination
}

// extractIperf3SeqNum extracts iperf3 sequence number from IP packet
func ExtractIperf3SeqNum(ipPacket []byte) (uint64, error) {
	fmt.Printf("=== PACKET STRUCTURE ANALYSIS ===\n")
	fmt.Printf("Total packet length: %d bytes\n", len(ipPacket))

	fmt.Printf("length of ipPacket: %d\n", len(ipPacket))
	// Check if we have Linux cooked capture header (16 bytes)

	// Basic IP header validation
	if len(ipPacket) < 20 {
		return 0, fmt.Errorf("packet too short for IP header")
	} else {
		fmt.Printf("Version: %02x, Len: %02x, Protocol(UDP 0x11, TCP 0x06):  %02x\n",
			(ipPacket[0] >> 4), (ipPacket[0] & 0x0F), ipPacket[9])
	}

	// Check if it's IPv4
	if (ipPacket[0] >> 4) != 4 {
		return 0, fmt.Errorf("not an IPv4 packet")
	}

	// Get IP header length
	ihl := int(ipPacket[0]&0x0F) * 4
	// Check if it's UDP (protocol 17)
	if ipPacket[9] != 17 {
		fmt.Printf("Protocol field: %d\n", ipPacket[9])
		return 0, fmt.Errorf("not a UDP packet")
	}

	udpPayloadStart := ihl + 8
	if len(ipPacket) < udpPayloadStart {
		return 0, fmt.Errorf("packet too short for UDP header")
	}

	// Extract UDP payload (skip IP header + 8 bytes UDP header)
	if len(ipPacket) < udpPayloadStart+12 {
		return 0, fmt.Errorf("packet too short for iperf3 header")
	}

	udpPayload := ipPacket[udpPayloadStart:]

	// Extract iperf3 sequence number (32-bit, big-endian, at offset 0)
	seqNum := uint64(udpPayload[8])<<24 |
		uint64(udpPayload[9])<<16 |
		uint64(udpPayload[10])<<8 |
		uint64(udpPayload[11])

	fmt.Printf("Extracted iperf3 sequence number: %d\n", seqNum)
	return seqNum, nil
}

// IsValidIPPacket checks if the data is a valid IPv4 packet
func IsValidIPPacket(data []byte) bool {
	if len(data) < 20 {
		return false
	}

	version := data[0] >> 4
	if version != 4 {
		return false
	}

	ihl := data[0] & 0x0F
	if ihl < 5 {
		return false
	}

	totalLength := int(data[2])<<8 | int(data[3])
	if totalLength < 20 || totalLength > len(data) {
		return false
	}

	// Additional check: ensure it's not all zeros or invalid patterns
	if data[0] == 0 && data[1] == 0 && data[2] == 0 && data[3] == 0 {
		return false
	}

	return true
}

// IsValidIPPacketVerbose checks if the data is a valid IPv4 packet with detailed error reporting
func IsValidIPPacketVerbose(data []byte) (bool, string) {
	if len(data) < 20 {
		return false, "packet too short"
	}

	version := data[0] >> 4
	if version != 4 {
		return false, "not IPv4"
	}

	ihl := data[0] & 0x0F
	if ihl < 5 {
		return false, "invalid header length"
	}

	totalLength := int(data[2])<<8 | int(data[3])
	if totalLength < 20 || totalLength > len(data) {
		return false, "invalid total length"
	}

	// Additional check: ensure it's not all zeros or invalid patterns
	if data[0] == 0 && data[1] == 0 && data[2] == 0 && data[3] == 0 {
		return false, "packet appears to be all zeros"
	}

	return true, ""
}

// IsUDPPacket checks if the IP packet contains UDP payload
func IsUDPPacket(data []byte) bool {
	if len(data) < 20 {
		return false
	}

	// Check if it's IPv4
	if (data[0] >> 4) != 4 {
		return false
	}

	// Check if protocol is UDP (17)
	return data[9] == 17
}

// IsTCPPacket checks if the IP packet contains TCP payload
func IsTCPPacket(data []byte) bool {
	if len(data) < 20 {
		return false
	}

	// Check if it's IPv4
	if (data[0] >> 4) != 4 {
		return false
	}

	// Check if protocol is TCP (6)
	return data[9] == 6
}
