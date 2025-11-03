package server

import (
	"context"
	"net"

	"github.com/HanHongChen/dp-udp/constant"
	"github.com/HanHongChen/dp-udp/logger"
	"github.com/HanHongChen/dp-udp/model"
	"github.com/HanHongChen/dp-udp/tun"
	"github.com/HanHongChen/dp-udp/util"

	"github.com/cespare/xxhash/v2"

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
	readFromUdp1 chan []byte
	readFromUdp2 chan []byte

	writeToTun chan []byte

	// Client address mapping
	clientAddrs1 *hashmap.Map[string, *net.UDPAddr]
	clientAddrs2 *hashmap.Map[string, *net.UDPAddr]

	packetMap *hashmap.Map[uint64, struct{}]
	iperfMap  *hashmap.Map[uint64, struct{}]
	// Thread-safe packet Eliminator
	count uint64

	*logger.ServerLogger
}

func NewDpUdpServer(config *model.ServerConfig, serverLogger *logger.ServerLogger) *DpUdpServer {
	return &DpUdpServer{
		udpServer1: newUdpServer(config.ServerIE.UDP1ListenAddr, config.ServerIE.UDP1ListenPort),
		udpServer2: newUdpServer(config.ServerIE.UDP2ListenAddr, config.ServerIE.UDP2ListenPort),

		tunnelDeviceName:  config.ServerIE.TunnelDevice.Name,
		tunnelDeviceIP:    config.ServerIE.TunnelDevice.IP,
		tunnelRoutePrefix: config.ServerIE.TunnelDevice.RoutePrefix,

		readFromTun:  make(chan []byte, 2097152),
		readFromUdp1: make(chan []byte, 2097152),
		readFromUdp2: make(chan []byte, 2097152),

		writeToTun: make(chan []byte, 2097152),

		count:        0,
		clientAddrs1: hashmap.New[string, *net.UDPAddr](),
		clientAddrs2: hashmap.New[string, *net.UDPAddr](),

		packetMap: hashmap.New[uint64, struct{}](),
		iperfMap:  hashmap.New[uint64, struct{}](),

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
	go s.dispatchFromTunnel(ctx)

	go s.readFromUdp1Connection(ctx)
	go s.readFromUdp2Connection(ctx)
	go s.writeToTunnelDevice(ctx)

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

	// Properly clean up tunnel device
	if s.tunnelDevice != nil {
		s.ServerLog.Infof("Cleaning up tunnel device...")

		// First close the device file descriptor
		s.tunnelDevice.Close()

		// Then clean up the network configuration
		if err := tun.BringDownUeTunnelDevice(s.tunnelDeviceName, s.tunnelDeviceIP, s.tunnelRoutePrefix); err != nil {
			s.ServerLog.Errorf("Failed to bring down tunnel device: %v", err)
		} else {
			s.ServerLog.Infof("Tunnel device cleaned up successfully")
		}
	}

	s.ServerLog.Infof("DpUdpServer stopped")
	s.ServerLog.Warnf("count = %d", s.count)
}

func (s *DpUdpServer) initTunnelDevice() error {
	tunnelDevice, err := tun.CreateTunnelDevice(s.tunnelDeviceName, s.tunnelDeviceIP, s.tunnelRoutePrefix)
	if err != nil {
		return err
	}
	s.tunnelDevice = tunnelDevice
	return nil
}

// Read packets from the tunnel device and forward to UDP connections
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
			if !util.IsValidIPPacket(buffer) {
				s.ServerLog.Debugf("Invalid IP packet read from TUN device, skipping (size: %d)", len(buffer))
				continue
			}
			data := make([]byte, n)
			copy(data, buffer[:n])

			s.readFromTun <- data
		}
	}
}

// Read from udp server 1 and forward to tunnel device
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
			if !util.IsValidIPPacket(buffer) {
				s.ServerLog.Debugf("Invalid IP packet read from UDP conn 1, skipping (size: %d)", len(buffer))
				continue
			}
			// Receive raw IP packet directly
			data := make([]byte, n)
			copy(data, buffer[:n])

			// Store client address for response routing
			clientKey := addr.String()
			s.clientAddrs1.Set(clientKey, addr)
			s.writeToTun <- data
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
			if !util.IsValidIPPacket(buffer) {
				s.ServerLog.Debugf("Invalid IP packet read from UDP conn 2, skipping (size: %d)", len(buffer))
				continue
			}
			// Receive raw IP packet directly
			data := make([]byte, n)
			copy(data, buffer[:n])

			// Store client address for response routing
			clientKey := addr.String()
			s.clientAddrs2.Set(clientKey, addr)
			s.writeToTun <- data
		}
	}
}

func (s *DpUdpServer) writeToTunnelDevice(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case data := <-s.writeToTun:

			if s.packetEliminate(data) {
				continue
			}

			// if isIperf, seq := util.IsIperf3Datagram(data); isIperf {
			// 	s.ServerLog.Warnf("寫入 seq = %d\n", seq)
			// }
			s.count++
			if _, err := s.tunnelDevice.Write(data); err != nil {
				s.ServerLog.Errorf("Write to tunnel device failed: %v", err)
			}
		}
	}
}

func (s *DpUdpServer) packetEliminate(packet []byte) bool {
	if isIperf, seq := util.IsIperf3Datagram(packet); isIperf {
		if _, ok := s.iperfMap.Get(seq); ok {
			// s.iperfMap.Del(seq)
			s.TunLog.Debugf("Eliminated iperf3 packet seq %d", seq)
			s.TunLog.Tracef("Eliminated iperf3 packet seq %d, %x", seq, packet)
			return true
		}
		s.iperfMap.Set(seq, struct{}{})
	} else {
		h := xxhash.Sum64(packet)
		if _, ok := s.packetMap.Get(h); ok {
			s.packetMap.Del(h)
			s.TunLog.Debugf("Eliminated packet %d", h)
			s.TunLog.Tracef("Eliminated packet %d, %x", h, packet)
			return true
		}
		// s.writeToTun <- packet
		s.packetMap.Set(h, struct{}{})
		s.TunLog.Debugf("Packet %d stored", h)
		s.TunLog.Tracef("Packet %d stored, %x", h, packet)
	}

	return false

}

// Dispatch packets read from tunnel device to all connected UDP clients
func (s *DpUdpServer) dispatchFromTunnel(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case data := <-s.readFromTun:
			// Dispatch to all connected clients on both UDP connections
			data1 := make([]byte, len(data))
			copy(data1, data)
			data2 := make([]byte, len(data))
			copy(data2, data)

			go func() {
				s.clientAddrs1.Range(func(key string, addr *net.UDPAddr) bool {
					if err := s.udpServer1.write(data1, addr); err != nil {
						s.ServerLog.Errorf("UDP 1 server write to %s failed: %v", addr, err)
					}
					return true
				})
			}()

			go func() {
				s.clientAddrs2.Range(func(key string, addr *net.UDPAddr) bool {
					if err := s.udpServer2.write(data2, addr); err != nil {
						s.ServerLog.Errorf("UDP 2 server write to %s failed: %v", addr, err)
					}
					return true
				})
			}()
		}
	}
}
