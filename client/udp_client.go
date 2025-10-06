package client

import (
	"context"

	"github.com/HanHongChen/dp-udp/constant"
	"github.com/HanHongChen/dp-udp/logger"
	"github.com/HanHongChen/dp-udp/model"
	"github.com/HanHongChen/dp-udp/tun"
	"github.com/HanHongChen/dp-udp/util"
	"github.com/cornelk/hashmap"
	"github.com/songgao/water"
)

type DpUdpClient struct {
	udpClient1 *udpClient
	udpClient2 *udpClient

	tunnelDeviceName  string
	tunnelDeviceIP    string
	tunnelRoutePrefix string

	tunnelDevice *water.Interface

	readFromTun  chan []byte
	readFromUdp1 chan []byte
	readFromUdp2 chan []byte

	writeToTun chan []byte

	packetEliminator  *model.PacketEliminator
	packetReorderator *model.PacketReorderator

	packetMap *hashmap.Map[uint64, struct{}]

	*logger.ClientLogger
}

func NewDpUdpClient(config *model.ClientConfig, clientLogger *logger.ClientLogger) *DpUdpClient {
	return &DpUdpClient{
		udpClient1: newUdpClient(config.ClientIE.UDP1BindAddr, config.ClientIE.UDP1BindPort, config.ClientIE.UDP1RemoteAddr, config.ClientIE.UDP1RemotePort),
		udpClient2: newUdpClient(config.ClientIE.UDP2BindAddr, config.ClientIE.UDP2BindPort, config.ClientIE.UDP2RemoteAddr, config.ClientIE.UDP2RemotePort),

		tunnelDeviceName:  config.ClientIE.TunnelDevice.Name,
		tunnelDeviceIP:    config.ClientIE.TunnelDevice.IP,
		tunnelRoutePrefix: config.ClientIE.TunnelDevice.RoutePrefix,

		readFromTun:  make(chan []byte),
		readFromUdp1: make(chan []byte),
		readFromUdp2: make(chan []byte),

		writeToTun: make(chan []byte),

		packetEliminator:  model.NewPacketEliminator(10000),
		packetReorderator: model.NewPacketReorderator(1000, 500),

		packetMap: hashmap.New[uint64, struct{}](),

		ClientLogger: clientLogger,
	}
}

func (c *DpUdpClient) Start(ctx context.Context) error {
	c.ClientLog.Infof("DpUdpClient starting...")

	// Initialize UDP connections
	if err := c.udpClient1.connect(); err != nil {
		c.ClientLog.Errorf("UDP 1 client connect failed: %v", err)
		return err
	}
	c.ClientLog.Infof("UDP 1 client connected to %s:%d", c.udpClient1.remoteAddr, c.udpClient1.remotePort)

	if err := c.udpClient2.connect(); err != nil {
		c.ClientLog.Errorf("UDP 2 client connect failed: %v", err)
		return err
	}
	c.ClientLog.Infof("UDP 2 client connected to %s:%d", c.udpClient2.remoteAddr, c.udpClient2.remotePort)

	// Initialize tunnel device
	if err := c.initTunnelDevice(); err != nil {
		c.ClientLog.Errorf("Tunnel device initialization failed: %v", err)
		return err
	}

	// Start goroutines
	go c.readFromTunnelDevice(ctx)
	go c.readFromUdp1Connection(ctx)
	go c.readFromUdp2Connection(ctx)
	go c.writeToTunnelDevice(ctx)
	go c.dispatchFromTunnel(ctx)

	c.ClientLog.Infof("DpUdpClient started successfully")
	return nil
}

func (c *DpUdpClient) Stop() {
	c.ClientLog.Infof("DpUdpClient stopping...")

	if c.udpClient1 != nil {
		c.udpClient1.close()
	}
	if c.udpClient2 != nil {
		c.udpClient2.close()
	}
	if c.tunnelDevice != nil {
		c.ClientLog.Infof("Cleaning up tunnel device...")

		// First close the device file descriptor
		c.tunnelDevice.Close()

		// Then clean up the network configuration using actual device name
		actualDevName := c.tunnelDevice.Name()
		if err := tun.BringDownUeTunnelDevice(actualDevName, c.tunnelDeviceIP, c.tunnelRoutePrefix); err != nil {
			c.ClientLog.Errorf("Failed to bring down tunnel device: %v", err)
		} else {
			c.ClientLog.Infof("Tunnel device cleaned up successfully")
		}
	}

	c.ClientLog.Infof("DpUdpClient stopped")
}

func (c *DpUdpClient) initTunnelDevice() error {
	tunnelDevice, err := tun.CreateTunnelDevice(c.tunnelDeviceName, c.tunnelDeviceIP, c.tunnelRoutePrefix)
	if err != nil {
		return err
	}
	c.tunnelDevice = tunnelDevice
	return nil
}

func (c *DpUdpClient) readFromTunnelDevice(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			buffer := make([]byte, constant.BUFFER_SIZE)
			n, err := c.tunnelDevice.Read(buffer)
			if err != nil {
				c.ClientLog.Errorf("Read from tunnel device failed: %v", err)
				continue
			}

			// Create a properly sized buffer
			data := make([]byte, n)
			copy(data, buffer[:n])

			// Validate IP packet before sending
			if !util.IsValidIPPacket(data) {
				c.ClientLog.Debugf("Invalid IP packet read from TUN device, skipping (size: %d)", len(data))
				continue
			}

			// // 分析封包內容
			// if len(data) >= 20 {
			// 	protocol := data[9]
			// 	srcIP := fmt.Sprintf("%d.%d.%d.%d", data[12], data[13], data[14], data[15])
			// 	dstIP := fmt.Sprintf("%d.%d.%d.%d", data[16], data[17], data[18], data[19])

			// 	c.ClientLog.Infof("=== TUN READ PACKET ===")
			// 	c.ClientLog.Infof("Size: %d bytes", len(data))
			// 	c.ClientLog.Infof("Protocol: %d", protocol)
			// 	c.ClientLog.Infof("%s -> %s", srcIP, dstIP)

			// 	if protocol == 6 {
			// 		c.ClientLog.Infof("*** SENDING TCP PACKET ***")
			// 		if len(data) >= 24 {
			// 			ihl := int(data[0]&0x0F) * 4
			// 			srcPort := uint16(data[ihl])<<8 | uint16(data[ihl+1])
			// 			dstPort := uint16(data[ihl+2])<<8 | uint16(data[ihl+3])
			// 			c.ClientLog.Infof("TCP: %s:%d -> %s:%d", srcIP, srcPort, dstIP, dstPort)
			// 		}
			// 	} else if protocol == 17 {
			// 		c.ClientLog.Infof("*** SENDING UDP PACKET ***")
			// 		if len(data) >= 24 {
			// 			ihl := int(data[0]&0x0F) * 4
			// 			srcPort := uint16(data[ihl])<<8 | uint16(data[ihl+1])
			// 			dstPort := uint16(data[ihl+2])<<8 | uint16(data[ihl+3])
			// 			c.ClientLog.Infof("UDP: %s:%d -> %s:%d", srcIP, srcPort, dstIP, dstPort)
			// 		}
			// 	} else {
			// 		c.ClientLog.Infof("*** OTHER PROTOCOL: %d ***", protocol)
			// 	}
			// 	c.ClientLog.Infof("=======================")
			// }

			c.readFromTun <- data
		}
	}
}

func (c *DpUdpClient) readFromUdp1Connection(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			buffer := make([]byte, constant.BUFFER_SIZE)
			n, err := c.udpClient1.read(buffer)
			if err != nil {
				c.ClientLog.Errorf("UDP 1 client read failed: %v", err)
				continue
			}

			data := make([]byte, n)
			copy(data, buffer[:n])
			if !util.IsValidIPPacket(data) {
				c.ClientLog.Debugf("Invalid IP packet read from UDP conn 1, skipping (size: %d)", len(data))
				continue
			}
			c.readFromUdp1 <- data

		}
	}
}

func (c *DpUdpClient) readFromUdp2Connection(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			buffer := make([]byte, constant.BUFFER_SIZE)
			n, err := c.udpClient2.read(buffer)
			if err != nil {
				c.ClientLog.Errorf("UDP 2 client read failed: %v", err)
				continue
			}

			data := make([]byte, n)
			copy(data, buffer[:n])
			if !util.IsValidIPPacket(data) {
				c.ClientLog.Debugf("Invalid IP packet read from UDP conn 2, skipping (size: %d)", len(data))
				continue
			}
			c.readFromUdp2 <- data

		}
	}
}

func (c *DpUdpClient) writeToTunnelDevice(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case data := <-c.writeToTun:
			if !util.IsValidIPPacket(data) {
				c.ClientLog.Debugf("Invalid IP packet from writeToTun channel, skipping")
				continue
			}
			if _, err := c.tunnelDevice.Write(data); err != nil {
				c.ClientLog.Errorf("Write to tunnel device failed: %v", err)
			}
		case data := <-c.readFromUdp1:
			c.ClientLog.Debugf("Writing %d bytes to TUN from UDP1", len(data))
			// isTcp, isUdp, seq, err := util.AnalyzePacket(data)
			// if err != nil {
			// 	c.ClientLog.Warnf("AnalyzePacket error: %v", err)
			// }

			// if isTcp || isUdp || seq == 0 {
			// 	c.ClientLog.Debugf("AnalyzePacket result - isTcp: %v, isUdp: %v, seq: %d", isTcp, isUdp, seq)
			// } else {
			// 	c.ClientLog.Debugf("Extracted iperf3 seq num from UDP1 data: %d", seq)
			// 	if c.packetEliminator.CheckAndMark(seq) {
			// 		c.ClientLog.Debugf("Packet seq %d eliminated as duplicate", seq)
			// 		continue
			// 	}
			// }
			if util.IsTCPPacket(data) {
				c.ClientLog.Debugf("Skipping TCP packet from UDP1 (likely iperf3 control)")
				// continue
			} else {
				seq, err := util.ExtractIperf3SeqNum(data)
				if err != nil {
					c.ClientLog.Warnf("Could not extract iperf3 seq num from UDP1 data: %v", err)
				} else {
					c.ClientLog.Debugf("Extracted iperf3 seq num from UDP1 data: %d", seq)
				}

				if c.packetEliminator.CheckAndMark(seq) {
					c.ClientLog.Debugf("Packet seq %d eliminated as duplicate", seq)
					continue
				}
			}

			// c.packetReorderator.AddPacket(seq, data)

			if _, err := c.tunnelDevice.Write(data); err != nil {
				c.ClientLog.Errorf("Write UDP1 data to tunnel device failed: %v", err)
			}
		case data := <-c.readFromUdp2:
			c.ClientLog.Debugf("Writing %d bytes to TUN from UDP2", len(data))
			// isTcp, isUdp, seq, err := util.AnalyzePacket(data)
			// if err != nil {
			// 	c.ClientLog.Warnf("AnalyzePacket error: %v", err)
			// }

			// if isTcp || isUdp || seq == 0 {
			// 	c.ClientLog.Debugf("AnalyzePacket result - isTcp: %v, isUdp: %v, seq: %d", isTcp, isUdp, seq)
			// } else {
			// 	c.ClientLog.Debugf("Extracted iperf3 seq num from UDP2 data: %d", seq)
			// 	if c.packetEliminator.CheckAndMark(seq) {
			// 		c.ClientLog.Debugf("Packet seq %d eliminated as duplicate", seq)
			// 		continue
			// 	}
			// }
			if util.IsTCPPacket(data) {
				c.ClientLog.Debugf("TCP packet from UDP2 (likely iperf3 control)")
				// continue
			} else {
				seq, err := util.ExtractIperf3SeqNum(data)
				if err != nil {
					c.ClientLog.Warnf("Could not extract iperf3 seq num from UDP2 data: %v", err)
				} else {
					c.ClientLog.Debugf("Extracted iperf3 seq num from UDP2 data: %d", seq)
				}

				if c.packetEliminator.CheckAndMark(seq) {
					c.ClientLog.Debugf("Packet seq %d eliminated as duplicate", seq)
					continue
				}

				// c.packetReorderator.AddPacket(seq, data)

			}

			if _, err := c.tunnelDevice.Write(data); err != nil {
				c.ClientLog.Errorf("Write UDP2 data to tunnel device failed: %v", err)
			}
			// case readyPackets := <-c.packetReorderator.GetReadyChan():
			// 	for _, packet := range readyPackets {
			// 		if _, err := c.tunnelDevice.Write(packet); err != nil {
			// 			c.ClientLog.Errorf("Write readyPackets to tunnel failed: %v", err)
			// 		}
			// 	}
		}

	}
}

func (c *DpUdpClient) dispatchFromTunnel(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case data := <-c.readFromTun:
			// Dispatch to both UDP connections with iperf3 headers
			go c.sendToUdp1(data)
			go c.sendToUdp2(data)
		}
	}
}

func (c *DpUdpClient) sendToUdp1(data []byte) {
	// Send raw IP packet directly - no additional encapsulation needed
	if err := c.udpClient1.write(data); err != nil {
		c.ClientLog.Errorf("UDP 1 client write failed: %v", err)
	}
}

func (c *DpUdpClient) sendToUdp2(data []byte) {
	// Send raw IP packet directly - no additional encapsulation needed
	if err := c.udpClient2.write(data); err != nil {
		c.ClientLog.Errorf("UDP 2 client write failed: %v", err)
	}
}
