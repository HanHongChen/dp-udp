package client

import (
	"context"
	"crypto/sha512"
	"sync"
	"sync/atomic"
	"time"

	"github.com/HanHongChen/dp-udp/constant"
	"github.com/HanHongChen/dp-udp/logger"
	"github.com/HanHongChen/dp-udp/model"
	"github.com/HanHongChen/dp-udp/tun"
	"github.com/HanHongChen/dp-udp/util"
	"github.com/songgao/water"
)

const (
	WRITE_BATCH_MAX   = 1000                  // batch size
	WRITE_BATCH_DELAY = 10 * time.Millisecond // batch delay time
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
	writeToUdp1  chan []byte
	writeToUdp2  chan []byte

	writeToTun    chan []byte
	eliminateChan chan []byte

	count    uint64
	dupCount uint64
	seqCount uint64
	count1   uint64

	packetMap sync.Map // key: uint64, value: struct{}
	iperfMap  sync.Map

	*logger.ClientLogger
}

func NewDpUdpClient(config *model.ClientConfig, clientLogger *logger.ClientLogger) *DpUdpClient {

	return &DpUdpClient{
		udpClient1: newUdpClient(config.ClientIE.UDP1BindAddr, config.ClientIE.UDP1BindPort, config.ClientIE.UDP1RemoteAddr, config.ClientIE.UDP1RemotePort),
		udpClient2: newUdpClient(config.ClientIE.UDP2BindAddr, config.ClientIE.UDP2BindPort, config.ClientIE.UDP2RemoteAddr, config.ClientIE.UDP2RemotePort),

		tunnelDeviceName:  config.ClientIE.TunnelDevice.Name,
		tunnelDeviceIP:    config.ClientIE.TunnelDevice.IP,
		tunnelRoutePrefix: config.ClientIE.TunnelDevice.RoutePrefix,

		readFromTun:  make(chan []byte, 10000),
		readFromUdp1: make(chan []byte, 10000),
		readFromUdp2: make(chan []byte, 10000),
		writeToUdp1:  make(chan []byte, 10000),
		writeToUdp2:  make(chan []byte, 10000),

		writeToTun:    make(chan []byte, 10000),
		eliminateChan: make(chan []byte),

		count:    0,
		dupCount: 0,
		seqCount: 0,
		count1:   0,

		// packetMap: hashmap.New[uint64, struct{}](),

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
	go c.dispatchFromTunnel(ctx)
	go c.sendToUdp1(ctx)
	go c.sendToUdp2(ctx)

	go c.readFromUdp1Connection(ctx)
	go c.readFromUdp2Connection(ctx)
	go c.writeToTunnelDevice(ctx)
	go c.startEliminatorWorkers(ctx)

	// go c.startRuntimeMonitor(ctx, "127.0.0.1:6061")

	c.ClientLog.Infof("DpUdpClient started successfully")
	return nil
}

// func (c *DpUdpClient) startRuntimeMonitor(ctx context.Context, addr string) {
// 	// pprof mux
// 	mux := http.NewServeMux()
// 	mux.HandleFunc("/debug/pprof/", pprof.Index)
// 	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
// 	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
// 	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
// 	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
// 	go func() {
// 		c.ClientLog.Infof("pprof listening on http://%s/debug/pprof/", addr)
// 		if err := http.ListenAndServe(addr, mux); err != nil {
// 			c.ClientLog.Errorf("pprof server error: %v", err)
// 		}
// 	}()

// 	tk := time.NewTicker(2 * time.Second)
// 	defer tk.Stop()

// 	var ms runtime.MemStats
// 	for {
// 		select {
// 		case <-ctx.Done():
// 			return
// 		case <-tk.C:
// 			runtime.ReadMemStats(&ms)
// 			g := runtime.NumGoroutine()
// 			c.ClientLog.Warnf(
// 				"[MON] goroutines=%d alloc=%dKB gc=%d ch{readTun=%d, wUdp1=%d, wUdp2=%d, wTun=%d, elim=%d}",
// 				g, ms.Alloc/1024, ms.NumGC,
// 				len(c.readFromTun), len(c.writeToUdp1), len(c.writeToUdp2),
// 				len(c.writeToTun), len(c.eliminateChan),
// 			)
// 		}
// 	}
// }

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
	c.ClientLog.Infof("count = %d", atomic.LoadUint64(&c.count))
	// c.ClientLog.Infof("seqCount = %d", atomic.LoadUint64(&c.seqCount))
	// c.ClientLog.Infof("count1 = %d", atomic.LoadUint64(&c.count1))

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
			// if isIperf, seq := util.IsIperf3Datagram(buffer); isIperf {
			// 	fmt.Printf("readFromTunnelDevice %d \n", seq)
			// 	// c.TunLog.Warnf("iperf3 client 送 seq %d \n", seq)
			// 	// c.seqCount++
			// }
			if !util.IsValidIPPacket(buffer) {
				c.ClientLog.Debugf("Invalid IP packet read from TUN device, skipping (size: %d)", n)
				continue
			}
			atomic.AddUint64(&c.count, 1)

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

			data := make([]byte, n)
			copy(data, buffer[:n])
			if !util.IsValidIPPacket(buffer) {
				c.ClientLog.Debugf("Invalid IP packet read from UDP conn 1, skipping (size: %d)", n)
				continue
			}
			c.eliminateChan <- data
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
			if !util.IsValidIPPacket(buffer) {
				c.ClientLog.Debugf("Invalid IP packet read from UDP conn 2, skipping (size: %d)", n)
				continue
			}
			c.eliminateChan <- data

		}
	}
}

func (c *DpUdpClient) writeToTunnelDevice(ctx context.Context) {

	for {
		select {
		case <-ctx.Done():
			return
		case data := <-c.writeToTun:
			// if isIperf, seq := util.IsIperf3Datagram(data); isIperf {
			// 	fmt.Printf("writeToTunnelDevice %d \n", seq)
			// 	// c.TunLog.Warnf("iperf3 client 送 seq %d \n", seq)
			// 	// c.seqCount++
			// }
			if _, err := c.tunnelDevice.Write(data); err != nil {
				c.ClientLog.Errorf("Write to tunnel device failed: %v", err)
			}

		}
	}

}

func (c *DpUdpClient) startEliminatorWorkers(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case packet := <-c.eliminateChan:
			if c.packetEliminate(packet) {
				continue
			}
			c.writeToTun <- packet
		}
	}
}

// true: packet eliminated, false: packet passed
func (c *DpUdpClient) packetEliminate(packet []byte) bool {
	if isIperf, seq := util.IsIperf3Datagram(packet); isIperf {
		_, loaded := c.iperfMap.LoadOrStore(seq, struct{}{})
		if loaded {
			c.TunLog.Debugf("Eliminated iperf3 packet seq %d", seq)
			c.TunLog.Tracef("Eliminated iperf3 packet seq %d, %x", seq, packet)
			return true
		}
	} else {
		// non-iperf3 packet elimination based on hash
		h := sha512.Sum512(packet)
		_, loaded := c.packetMap.LoadOrStore(h, struct{}{})
		if loaded {
			c.TunLog.Debugf("Eliminated packet %d", h)
			c.TunLog.Tracef("Eliminated packet %d, %x", h, packet)
			// atomic.AddUint64(&c.dupCount, 1)

			return true
		}
	}

	return false
}

func (c *DpUdpClient) dispatchFromTunnel(ctx context.Context) {

	for {
		select {
		case <-ctx.Done():
			return
		case data := <-c.readFromTun:
			c.writeToUdp1 <- data
			c.writeToUdp2 <- data
		}
	}
}

func (c *DpUdpClient) sendToUdp1(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case data := <-c.writeToUdp1:
			if err := c.udpClient1.write(data); err != nil {
				c.ClientLog.Errorf("UDP 1 client write failed: %v", err)
			}
		}
	}
}

func (c *DpUdpClient) sendToUdp2(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case data := <-c.writeToUdp2:
			if err := c.udpClient2.write(data); err != nil {
				c.ClientLog.Errorf("UDP 2 client write failed: %v", err)
			}
		}
	}
}
