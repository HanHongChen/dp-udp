package model

import (
	"testing"
)

func TestIperf3PacketFormat(t *testing.T) {
	// Test 32-bit format (standard iperf3)
	t.Run("32-bit format", func(t *testing.T) {
		seqNum := uint64(2) // From your Wireshark capture
		packet := NewUDPPacketDefault(seqNum, []byte("test payload"))

		// Marshal the packet
		data := packet.Marshal()

		// Should be 12 bytes header + payload
		expectedHeaderSize := 12
		if len(data) != expectedHeaderSize+len("test payload") {
			t.Errorf("Expected packet size %d, got %d", expectedHeaderSize+len("test payload"), len(data))
		}

		// Parse it back
		var parsedPacket UDPPacket
		err := parsedPacket.Unmarshal(data)
		if err != nil {
			t.Fatalf("Failed to unmarshal packet: %v", err)
		}

		// Check sequence number
		if parsedPacket.Header.SeqNum != seqNum {
			t.Errorf("Expected sequence number %d, got %d", seqNum, parsedPacket.Header.SeqNum)
		}

		// Check format detection
		if parsedPacket.Header.Is64Bit {
			t.Error("Expected 32-bit format, but detected as 64-bit")
		}

		// Check payload
		if string(parsedPacket.Payload) != "test payload" {
			t.Errorf("Expected payload 'test payload', got '%s'", string(parsedPacket.Payload))
		}
	})

	// Test 64-bit format
	t.Run("64-bit format", func(t *testing.T) {
		seqNum := uint64(0x123456789ABCDEF0) // Large 64-bit number
		packet := NewUDPPacket(seqNum, []byte("test payload"), true)

		// Marshal the packet
		data := packet.Marshal()

		// Should be 16 bytes header + payload
		expectedHeaderSize := 16
		if len(data) != expectedHeaderSize+len("test payload") {
			t.Errorf("Expected packet size %d, got %d", expectedHeaderSize+len("test payload"), len(data))
		}

		// Parse it back using 64-bit method
		var parsedPacket UDPPacket
		err := parsedPacket.Unmarshal64Bit(data)
		if err != nil {
			t.Fatalf("Failed to unmarshal packet: %v", err)
		}

		// Check sequence number
		if parsedPacket.Header.SeqNum != seqNum {
			t.Errorf("Expected sequence number %d, got %d", seqNum, parsedPacket.Header.SeqNum)
		}

		// Check format detection
		if !parsedPacket.Header.Is64Bit {
			t.Error("Expected 64-bit format, but detected as 32-bit")
		}
	})
}

func TestWiresharkCapture(t *testing.T) {
	// Simulate the exact packet from your Wireshark capture
	t.Run("Wireshark sample", func(t *testing.T) {
		// From the capture: iPerf3 sequence: 2
		seqNum := uint64(2)

		// Create packet similar to what iperf3 would send
		packet := NewUDPPacketDefault(seqNum, make([]byte, 1448-12)) // 1448 total - 12 header = 1436 payload

		// Set timestamp similar to capture (148646.8738650 seconds)
		packet.Header.Sec = 148646
		packet.Header.Usec = 873865

		data := packet.Marshal()

		// Total should be 1448 bytes (like in Wireshark)
		if len(data) != 1448 {
			t.Errorf("Expected total packet size 1448, got %d", len(data))
		}

		// Parse it back
		var parsedPacket UDPPacket
		err := parsedPacket.Unmarshal(data)
		if err != nil {
			t.Fatalf("Failed to unmarshal packet: %v", err)
		}

		// Verify sequence number
		if parsedPacket.Header.SeqNum != seqNum {
			t.Errorf("Expected sequence number %d, got %d", seqNum, parsedPacket.Header.SeqNum)
		}

		// Verify it's detected as 32-bit (standard iperf3)
		if parsedPacket.Header.Is64Bit {
			t.Error("Expected 32-bit format detection for standard iperf3 packet")
		}

		// Verify timestamp
		if parsedPacket.Header.Sec != 148646 {
			t.Errorf("Expected seconds %d, got %d", 148646, parsedPacket.Header.Sec)
		}

		if parsedPacket.Header.Usec != 873865 {
			t.Errorf("Expected microseconds %d, got %d", 873865, parsedPacket.Header.Usec)
		}
	})
}

func TestPacketFormatAutoDetection(t *testing.T) {
	tests := []struct {
		name     string
		seqNum   uint64
		use64Bit bool
		expected bool
	}{
		{"Small 32-bit sequence", 123, false, false},
		{"Large 32-bit sequence", 0xFFFFFFFF, false, false},
		{"Small 64-bit sequence", 123, true, true},
		{"Large 64-bit sequence", 0x123456789ABCDEF0, true, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			packet := NewUDPPacket(tt.seqNum, []byte("test"), tt.use64Bit)
			data := packet.Marshal()

			var parsedPacket UDPPacket
			var err error

			// Use appropriate unmarshal method based on expected format
			if tt.use64Bit {
				err = parsedPacket.Unmarshal64Bit(data)
			} else {
				err = parsedPacket.Unmarshal(data)
			}

			if err != nil {
				t.Fatalf("Failed to unmarshal packet: %v", err)
			}

			if parsedPacket.Header.Is64Bit != tt.expected {
				t.Errorf("Expected Is64Bit=%v, got %v", tt.expected, parsedPacket.Header.Is64Bit)
			}

			if parsedPacket.Header.SeqNum != tt.seqNum {
				t.Errorf("Expected sequence number %d, got %d", tt.seqNum, parsedPacket.Header.SeqNum)
			}
		})
	}
}
