package client

import (
	"context"
	"sync/atomic"

	"github.com/HanHongChen/dp-udp/constant"
	"github.com/HanHongChen/dp-udp/logger"
	"github.com/HanHongChen/dp-udp/model"
	"github.com/HanHongChen/dp-udp/tun"
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

	// Packet deduplication
	deduplicator1 *model.PacketDeduplicator
	deduplicator2 *model.PacketDeduplicator

	// Sequence numbers for outgoing packets
	seqNum1 *uint64
	seqNum2 *uint64

	packetMap *hashmap.Map[uint64, struct{}]

	*logger.ClientLogger
}

func NewDpUdpClient(config *model.ClientConfig, clientLogger *logger.ClientLogger) *DpUdpClient {
	var seq1, seq2 uint64
	return &DpUdpClient{
		udpClient1: newUdpClient(config.ClientIE.UDP1DialAddr, config.ClientIE.UDP1DialPort, config.ClientIE.UDP1ConnAddr, config.ClientIE.UDP1ConnPort),
		udpClient2: newUdpClient(config.ClientIE.UDP2DialAddr, config.ClientIE.UDP2DialPort, config.ClientIE.UDP2ConnAddr, config.ClientIE.UDP2ConnPort),

		tunnelDeviceName:  config.ClientIE.TunnelDevice.Name,
		tunnelDeviceIP:    config.ClientIE.TunnelDevice.IP,
		tunnelRoutePrefix: config.ClientIE.TunnelDevice.RoutePrefix,

		readFromTun:  make(chan []byte),
		readFromUdp1: make(chan []byte),
		readFromUdp2: make(chan []byte),

		writeToTun: make(chan []byte),

		deduplicator1: model.NewPacketDeduplicator(),
		deduplicator2: model.NewPacketDeduplicator(),

		seqNum1: &seq1,
		seqNum2: &seq2,

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
	c.ClientLog.Infof("UDP 1 client connected to %s:%d", c.udpClient1.dialAddr, c.udpClient1.dialPort)

	if err := c.udpClient2.connect(); err != nil {
		c.ClientLog.Errorf("UDP 2 client connect failed: %v", err)
		return err
	}
	c.ClientLog.Infof("UDP 2 client connected to %s:%d", c.udpClient2.dialAddr, c.udpClient2.dialPort)

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
		c.tunnelDevice.Close()
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

			// Parse iperf3 UDP packet
			var packet model.UDPPacket
			if err := packet.Unmarshal(buffer[:n]); err != nil {
				c.ClientLog.Errorf("Failed to parse UDP packet from connection 1: %v", err)
				continue
			}

			// Process packet for deduplication
			shouldProcess, stats := c.deduplicator1.ProcessPacket(packet.Header.SeqNum)

			if stats.IsDuplicate {
				c.ClientLog.Debugf("Duplicate packet on UDP1, seq=%d", packet.Header.SeqNum)
				continue
			}

			if stats.IsOutOfOrder {
				c.ClientLog.Debugf("Out-of-order packet on UDP1, seq=%d, expected>%d", packet.Header.SeqNum, stats.MaxSeqNum)
			}

			if shouldProcess {
				c.readFromUdp1 <- packet.Payload
			}
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

			// Parse iperf3 UDP packet
			var packet model.UDPPacket
			if err := packet.Unmarshal(buffer[:n]); err != nil {
				c.ClientLog.Errorf("Failed to parse UDP packet from connection 2: %v", err)
				continue
			}

			// Process packet for deduplication
			shouldProcess, stats := c.deduplicator2.ProcessPacket(packet.Header.SeqNum)

			if stats.IsDuplicate {
				c.ClientLog.Debugf("Duplicate packet on UDP2, seq=%d", packet.Header.SeqNum)
				continue
			}

			if stats.IsOutOfOrder {
				c.ClientLog.Debugf("Out-of-order packet on UDP2, seq=%d, expected>%d", packet.Header.SeqNum, stats.MaxSeqNum)
			}

			if shouldProcess {
				c.readFromUdp2 <- packet.Payload
			}
		}
	}
}

func (c *DpUdpClient) writeToTunnelDevice(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case data := <-c.writeToTun:
			if _, err := c.tunnelDevice.Write(data); err != nil {
				c.ClientLog.Errorf("Write to tunnel device failed: %v", err)
			}
		case data := <-c.readFromUdp1:
			if _, err := c.tunnelDevice.Write(data); err != nil {
				c.ClientLog.Errorf("Write UDP1 data to tunnel device failed: %v", err)
			}
		case data := <-c.readFromUdp2:
			if _, err := c.tunnelDevice.Write(data); err != nil {
				c.ClientLog.Errorf("Write UDP2 data to tunnel device failed: %v", err)
			}
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
	seq := atomic.AddUint64(c.seqNum1, 1)
	packet := model.NewUDPPacketDefault(seq, data) // Use standard iperf3 32-bit format
	packetBytes := packet.Marshal()

	if err := c.udpClient1.write(packetBytes); err != nil {
		c.ClientLog.Errorf("UDP 1 client write failed: %v", err)
	}
}

func (c *DpUdpClient) sendToUdp2(data []byte) {
	seq := atomic.AddUint64(c.seqNum2, 1)
	packet := model.NewUDPPacketDefault(seq, data) // Use standard iperf3 32-bit format
	packetBytes := packet.Marshal()

	if err := c.udpClient2.write(packetBytes); err != nil {
		c.ClientLog.Errorf("UDP 2 client write failed: %v", err)
	}
}
