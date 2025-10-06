package server

import (
	"context"
	"net"

	"github.com/HanHongChen/dp-udp/constant"
	"github.com/HanHongChen/dp-udp/logger"
	"github.com/HanHongChen/dp-udp/model"
	"github.com/HanHongChen/dp-udp/tun"
	"github.com/HanHongChen/dp-udp/util"
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

	// Thread-safe packet Eliminator
	packetEliminator  *model.PacketEliminator
	packetReorderator *model.PacketReorderator

	*logger.ServerLogger
}

func NewDpUdpServer(config *model.ServerConfig, serverLogger *logger.ServerLogger) *DpUdpServer {
	return &DpUdpServer{
		udpServer1: newUdpServer(config.ServerIE.UDP1ListenAddr, config.ServerIE.UDP1ListenPort),
		udpServer2: newUdpServer(config.ServerIE.UDP2ListenAddr, config.ServerIE.UDP2ListenPort),

		tunnelDeviceName:  config.ServerIE.TunnelDevice.Name,
		tunnelDeviceIP:    config.ServerIE.TunnelDevice.IP,
		tunnelRoutePrefix: config.ServerIE.TunnelDevice.RoutePrefix,

		readFromTun:  make(chan []byte),
		readFromUdp1: make(chan []byte),
		readFromUdp2: make(chan []byte),

		writeToTun: make(chan []byte),

		packetEliminator:  model.NewPacketEliminator(10000),
		packetReorderator: model.NewPacketReorderator(1000, 500),

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

			data := make([]byte, n)
			copy(data, buffer[:n])
			if !util.IsValidIPPacket(data) {
				s.ServerLog.Debugf("Invalid IP packet read from TUN device, skipping (size: %d)", len(data))
				continue
			}

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

			// Receive raw IP packet directly
			data := make([]byte, n)
			copy(data, buffer[:n])
			if !util.IsValidIPPacket(data) {
				s.ServerLog.Debugf("Invalid IP packet read from UDP conn 1, skipping (size: %d)", len(data))
				continue
			}
			// s.ServerLog.Debugf("UDP1 received %d bytes from %s: %x", len(data), addr.String(), data)
			// Store client address for response routing
			clientKey := addr.String()
			s.clientAddrs1.Set(clientKey, addr)
			s.readFromUdp1 <- data

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

			// Receive raw IP packet directly
			data := make([]byte, n)
			copy(data, buffer[:n])
			if !util.IsValidIPPacket(data) {
				s.ServerLog.Debugf("Invalid IP packet read from UDP conn 2, skipping (size: %d)", len(data))
				continue
			}
			// s.ServerLog.Debugf("UDP2 received %d bytes from %s: %x", len(data), addr.String(), data)
			// Store client address for response routing
			clientKey := addr.String()
			s.clientAddrs2.Set(clientKey, addr)
			s.readFromUdp2 <- data

		}
	}
}

func (s *DpUdpServer) writeToTunnelDevice(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case data := <-s.writeToTun:
			if !util.IsValidIPPacket(data) {
				s.ServerLog.Debugf("Invalid IP packet from writeToTun channel, skipping")
				continue
			}
			if _, err := s.tunnelDevice.Write(data); err != nil {
				s.ServerLog.Errorf("Write to tunnel device failed: %v", err)
			}
		case data := <-s.readFromUdp1:
			s.ServerLog.Debugf("Writing %d bytes to TUN from UDP1", len(data))
			// isTcp, isUdp, seq, err := util.AnalyzePacket(data)
			// if err != nil {
			// 	s.ServerLog.Warnf("AnalyzePacket error: %v", err)
			// }

			// if isTcp || isUdp || seq == 0 {
			// 	s.ServerLog.Debugf("AnalyzePacket result - isTcp: %v, isUdp: %v, seq: %d", isTcp, isUdp, seq)
			// } else {
			// 	s.ServerLog.Debugf("Extracted iperf3 seq num from UDP1 data: %d", seq)
			// 	if s.packetEliminator.CheckAndMark(seq) {
			// 		s.ServerLog.Debugf("Packet seq %d eliminated as duplicate", seq)
			// 		continue
			// 	}
			// }
			if util.IsTCPPacket(data) {
				s.ServerLog.Debugf("Skipping TCP packet from UDP1 (likely iperf3 control)")
			} else {
				seq, err := util.ExtractIperf3SeqNum(data)
				if err != nil {
					s.ServerLog.Warnf("Could not extract iperf3 seq num from UDP1 data: %v", err)
				} else {
					s.ServerLog.Debugf("Extracted iperf3 seq num from UDP1 data: %d", seq)
				}

				if s.packetEliminator.CheckAndMark(seq) {
					s.ServerLog.Debugf("Packet seq %d eliminated as duplicate", seq)
					continue
				}

				// s.packetReorderator.AddPacket(seq, data)

			}

			if _, err := s.tunnelDevice.Write(data); err != nil {
				s.ServerLog.Errorf("Write UDP1 data to tunnel device failed: %v", err)
			}
		case data := <-s.readFromUdp2:
			s.ServerLog.Debugf("Writing %d bytes to TUN from UDP2", len(data))
			// isTcp, isUdp, seq, err := util.AnalyzePacket(data)
			// if err != nil {
			// 	s.ServerLog.Warnf("AnalyzePacket error: %v", err)
			// 	return
			// }

			// if isTcp || isUdp || seq == 0 {
			// 	s.ServerLog.Debugf("AnalyzePacket result - isTcp: %v, isUdp: %v, seq: %d", isTcp, isUdp, seq)
			// } else {
			// 	s.ServerLog.Debugf("Extracted iperf3 seq num from UDP2 data: %d", seq)
			// 	if s.packetEliminator.CheckAndMark(seq) {
			// 		s.ServerLog.Debugf("Packet seq %d eliminated as duplicate", seq)
			// 		continue
			// 	}
			// }
			if util.IsTCPPacket(data) {
				s.ServerLog.Debugf("Skipping TCP packet from UDP2 (likely iperf3 control)")
				// continue
			} else {
				seq, err := util.ExtractIperf3SeqNum(data)
				if err != nil {
					s.ServerLog.Warnf("Could not extract iperf3 seq num from UDP2 data: %v", err)
				} else {
					s.ServerLog.Debugf("Extracted iperf3 seq num from UDP2 data: %d", seq)
				}

				if s.packetEliminator.CheckAndMark(seq) {
					s.ServerLog.Debugf("Packet seq %d eliminated as duplicate", seq)
					continue
				}

				// s.packetReorderator.AddPacket(seq, data)

			}

			// // 印出整個封包內容
			// s.ServerLog.Infof("=== UDP1 PACKET ANALYSIS ===")
			// s.ServerLog.Infof("Packet size: %d bytes", len(data))
			// s.ServerLog.Infof("Raw hex: %x", data)

			// if len(data) >= 20 {
			// 	version := data[0] >> 4
			// 	ihl := (data[0] & 0x0F) * 4
			// 	protocol := data[9]
			// 	srcIP := fmt.Sprintf("%d.%d.%d.%d", data[12], data[13], data[14], data[15])
			// 	dstIP := fmt.Sprintf("%d.%d.%d.%d", data[16], data[17], data[18], data[19])

			// 	s.ServerLog.Infof("IP: Version=%d, IHL=%d, Protocol=%d", version, ihl, protocol)
			// 	s.ServerLog.Infof("IP: %s -> %s", srcIP, dstIP)

			// 	if protocol == 6 {
			// 		s.ServerLog.Infof("*** This is TCP packet ***")
			// 	} else if protocol == 17 {
			// 		s.ServerLog.Infof("*** This is UDP packet ***")
			// 		if len(data) >= int(ihl)+4 {
			// 			srcPort := uint16(data[ihl])<<8 | uint16(data[ihl+1])
			// 			dstPort := uint16(data[ihl+2])<<8 | uint16(data[ihl+3])
			// 			s.ServerLog.Infof("UDP: %s:%d -> %s:%d", srcIP, srcPort, dstIP, dstPort)
			// 		}
			// 	} else {
			// 		s.ServerLog.Infof("*** Protocol %d ***", protocol)
			// 	}
			// }
			// s.ServerLog.Infof("============================")

			if _, err := s.tunnelDevice.Write(data); err != nil {
				s.ServerLog.Errorf("Write UDP2 data to tunnel device failed: %v", err)
			}

			// case readyPackets := <-s.packetReorderator.GetReadyChan():
			// 	for _, packet := range readyPackets {
			// 		if _, err := s.tunnelDevice.Write(packet); err != nil {
			// 			s.ServerLog.Errorf("Write readyPackets to tunnel failed: %v", err)
			// 		}
			// 	}

		}
	}
}

// Dispatch packets read from tunnel device to all connected UDP clients
func (s *DpUdpServer) dispatchFromTunnel(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case data := <-s.readFromTun:
			// Dispatch to all connected clients on both UDP connections
			go func() {
				s.clientAddrs1.Range(func(key string, addr *net.UDPAddr) bool {
					if err := s.udpServer1.write(data, addr); err != nil {
						s.ServerLog.Errorf("UDP 1 server write to %s failed: %v", addr, err)
					}
					return true
				})
			}()

			go func() {
				s.clientAddrs2.Range(func(key string, addr *net.UDPAddr) bool {
					if err := s.udpServer2.write(data, addr); err != nil {
						s.ServerLog.Errorf("UDP 2 server write to %s failed: %v", addr, err)
					}
					return true
				})
			}()
		}
	}
}
