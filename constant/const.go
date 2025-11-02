package constant

const (
	BUFFER_SIZE           = 65535
	UDP_HEADER_SIZE_32BIT = 12                    // iperf3 UDP header size (sec:4 + usec:4 + seq:4)
	UDP_HEADER_SIZE_64BIT = 16                    // iperf3 UDP header size (sec:4 + usec:4 + seq:8)
	UDP_HEADER_SIZE       = UDP_HEADER_SIZE_64BIT // Default to 64-bit mode
)

const (
	CONFIG_TAG = "CONFIG"

	SERVER_TAG = "SERVER"

	CLIENT_TAG = "CLIENT"

	UDP_1_TAG = "UDP_1"
	UDP_2_TAG = "UDP_2"

	TUN_TAG = "TUN"
)
