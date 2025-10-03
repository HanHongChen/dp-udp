package server

import (
	"context"
	"net"
	"sync/atomic"

	"github.com/HanHongChen/dp-udp/constant"
	"github.com/HanHongChen/dp-udp/logger"
	"github.com/HanHongChen/dp-udp/model"
	"github.com/HanHongChen/dp-udp/tun"
	"github.com/cornelk/hashmap"
	"github.com/songgao/water"
)

type DpUdpServer struct {
	udpServer1 *udpServer
	udpServer2 *udpServer

	tunnelDeviceName  string
	tunnelDeviceIP    string
	tunnelRoutePrefix string

	tunnelDevice *water.Interface

	readFromTun  chan []byte
	readFromUdp1 chan UDPMessage
	readFromUdp2 chan UDPMessage

	writeToTun chan []byte

	// Packet deduplication
	deduplicator1 *model.PacketDeduplicator
	deduplicator2 *model.PacketDeduplicator

	// Sequence numbers for outgoing packets
	seqNum1 *uint64
	seqNum2 *uint64

	// Client address mapping
	clientAddrs1 *hashmap.Map[string, *net.UDPAddr]
	clientAddrs2 *hashmap.Map[string, *net.UDPAddr]

	packetMap *hashmap.Map[uint64, struct{}]

	*logger.ServerLogger
}

// UDPMessage represents a UDP message with sender address
type UDPMessage struct {
	Data []byte
	Addr *net.UDPAddr
}

func NewDpUdpServer(config *model.ServerConfig, serverLogger *logger.ServerLogger) *DpUdpServer {
	var seq1, seq2 uint64
	return &DpUdpServer{
		udpServer1: newUdpServer(config.ServerIE.UDP1ListenAddr, config.ServerIE.UDP1ListenPort),
		udpServer2: newUdpServer(config.ServerIE.UDP2ListenAddr, config.ServerIE.UDP2ListenPort),

		tunnelDeviceName:  config.ServerIE.TunnelDevice.Name,
		tunnelDeviceIP:    config.ServerIE.TunnelDevice.IP,
		tunnelRoutePrefix: config.ServerIE.TunnelDevice.RoutePrefix,

		readFromTun:  make(chan []byte),
		readFromUdp1: make(chan UDPMessage),
		readFromUdp2: make(chan UDPMessage),

		writeToTun: make(chan []byte),

		deduplicator1: model.NewPacketDeduplicator(),
		deduplicator2: model.NewPacketDeduplicator(),

		seqNum1: &seq1,
		seqNum2: &seq2,

		clientAddrs1: hashmap.New[string, *net.UDPAddr](),
		clientAddrs2: hashmap.New[string, *net.UDPAddr](),

		packetMap: hashmap.New[uint64, struct{}](),

		ServerLogger: serverLogger,
	}
}

func (s *DpUdpServer) Start(ctx context.Context) error {
	s.ServerLog.Infof("DpUdpServer starting...")

	// Start listening on UDP ports
	if err := s.udpServer1.listen(); err != nil {
		s.ServerLog.Errorf("UDP 1 server listen failed: %v", err)
		return err
	}
	s.ServerLog.Infof("UDP 1 server listening on %s:%d", s.udpServer1.listenAddr, s.udpServer1.listenPort)

	if err := s.udpServer2.listen(); err != nil {
		s.ServerLog.Errorf("UDP 2 server listen failed: %v", err)
		return err
	}
	s.ServerLog.Infof("UDP 2 server listening on %s:%d", s.udpServer2.listenAddr, s.udpServer2.listenPort)

	// Initialize tunnel device
	if err := s.initTunnelDevice(); err != nil {
		s.ServerLog.Errorf("Tunnel device initialization failed: %v", err)
		return err
	}

	// Start goroutines
	go s.readFromTunnelDevice(ctx)
	go s.readFromUdp1Connection(ctx)
	go s.readFromUdp2Connection(ctx)
	go s.writeToTunnelDevice(ctx)
	go s.dispatchFromTunnel(ctx)

	s.ServerLog.Infof("DpUdpServer started successfully")
	return nil
}

func (s *DpUdpServer) Stop() {
	s.ServerLog.Infof("DpUdpServer stopping...")

	if s.udpServer1 != nil {
		s.udpServer1.close()
	}
	if s.udpServer2 != nil {
		s.udpServer2.close()
	}
	if s.tunnelDevice != nil {
		s.tunnelDevice.Close()
	}

	s.ServerLog.Infof("DpUdpServer stopped")
}

func (s *DpUdpServer) initTunnelDevice() error {
	tunnelDevice, err := tun.CreateTunnelDevice(s.tunnelDeviceName, s.tunnelDeviceIP, s.tunnelRoutePrefix)
	if err != nil {
		return err
	}
	s.tunnelDevice = tunnelDevice
	return nil
}

func (s *DpUdpServer) readFromTunnelDevice(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			buffer := make([]byte, constant.BUFFER_SIZE)
			n, err := s.tunnelDevice.Read(buffer)
			if err != nil {
				s.ServerLog.Errorf("Read from tunnel device failed: %v", err)
				continue
			}

			// Create a properly sized buffer
			data := make([]byte, n)
			copy(data, buffer[:n])

			s.readFromTun <- data
		}
	}
}

func (s *DpUdpServer) readFromUdp1Connection(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			buffer := make([]byte, constant.BUFFER_SIZE)
			n, addr, err := s.udpServer1.read(buffer)
			if err != nil {
				s.ServerLog.Errorf("UDP 1 server read failed: %v", err)
				continue
			}

			// Parse iperf3 UDP packet
			var packet model.UDPPacket
			if err := packet.Unmarshal(buffer[:n]); err != nil {
				s.ServerLog.Errorf("Failed to parse UDP packet from connection 1: %v", err)
				continue
			}

			// Store client address for response routing
			clientKey := addr.String()
			s.clientAddrs1.Set(clientKey, addr)

			// Process packet for deduplication
			shouldProcess, stats := s.deduplicator1.ProcessPacket(packet.Header.SeqNum)

			if stats.IsDuplicate {
				s.ServerLog.Debugf("Duplicate packet on UDP1, seq=%d from %s", packet.Header.SeqNum, addr)
				continue
			}

			if stats.IsOutOfOrder {
				s.ServerLog.Debugf("Out-of-order packet on UDP1, seq=%d, expected>%d from %s", packet.Header.SeqNum, stats.MaxSeqNum, addr)
			}

			if shouldProcess {
				s.readFromUdp1 <- UDPMessage{Data: packet.Payload, Addr: addr}
			}
		}
	}
}

func (s *DpUdpServer) readFromUdp2Connection(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			buffer := make([]byte, constant.BUFFER_SIZE)
			n, addr, err := s.udpServer2.read(buffer)
			if err != nil {
				s.ServerLog.Errorf("UDP 2 server read failed: %v", err)
				continue
			}

			// Parse iperf3 UDP packet
			var packet model.UDPPacket
			if err := packet.Unmarshal(buffer[:n]); err != nil {
				s.ServerLog.Errorf("Failed to parse UDP packet from connection 2: %v", err)
				continue
			}

			// Store client address for response routing
			clientKey := addr.String()
			s.clientAddrs2.Set(clientKey, addr)

			// Process packet for deduplication
			shouldProcess, stats := s.deduplicator2.ProcessPacket(packet.Header.SeqNum)

			if stats.IsDuplicate {
				s.ServerLog.Debugf("Duplicate packet on UDP2, seq=%d from %s", packet.Header.SeqNum, addr)
				continue
			}

			if stats.IsOutOfOrder {
				s.ServerLog.Debugf("Out-of-order packet on UDP2, seq=%d, expected>%d from %s", packet.Header.SeqNum, stats.MaxSeqNum, addr)
			}

			if shouldProcess {
				s.readFromUdp2 <- UDPMessage{Data: packet.Payload, Addr: addr}
			}
		}
	}
}

func (s *DpUdpServer) writeToTunnelDevice(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case data := <-s.writeToTun:
			if _, err := s.tunnelDevice.Write(data); err != nil {
				s.ServerLog.Errorf("Write to tunnel device failed: %v", err)
			}
		case msg := <-s.readFromUdp1:
			if _, err := s.tunnelDevice.Write(msg.Data); err != nil {
				s.ServerLog.Errorf("Write UDP1 data to tunnel device failed: %v", err)
			}
		case msg := <-s.readFromUdp2:
			if _, err := s.tunnelDevice.Write(msg.Data); err != nil {
				s.ServerLog.Errorf("Write UDP2 data to tunnel device failed: %v", err)
			}
		}
	}
}

func (s *DpUdpServer) dispatchFromTunnel(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case data := <-s.readFromTun:
			// Dispatch to all connected clients on both UDP connections
			go s.broadcastToUdp1Clients(data)
			go s.broadcastToUdp2Clients(data)
		}
	}
}

func (s *DpUdpServer) broadcastToUdp1Clients(data []byte) {
	seq := atomic.AddUint64(s.seqNum1, 1)
	packet := model.NewUDPPacketDefault(seq, data) // Use standard iperf3 32-bit format
	packetBytes := packet.Marshal()

	// Send to all connected clients on UDP1
	s.clientAddrs1.Range(func(key string, addr *net.UDPAddr) bool {
		if err := s.udpServer1.write(packetBytes, addr); err != nil {
			s.ServerLog.Errorf("UDP 1 server write to %s failed: %v", addr, err)
		}
		return true
	})
}

func (s *DpUdpServer) broadcastToUdp2Clients(data []byte) {
	seq := atomic.AddUint64(s.seqNum2, 1)
	packet := model.NewUDPPacketDefault(seq, data) // Use standard iperf3 32-bit format
	packetBytes := packet.Marshal()

	// Send to all connected clients on UDP2
	s.clientAddrs2.Range(func(key string, addr *net.UDPAddr) bool {
		if err := s.udpServer2.write(packetBytes, addr); err != nil {
			s.ServerLog.Errorf("UDP 2 server write to %s failed: %v", addr, err)
		}
		return true
	})
}
