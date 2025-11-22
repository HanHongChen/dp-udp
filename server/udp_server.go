package server

import (
	"context"
	"crypto/sha512"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/HanHongChen/dp-udp/constant"
	"github.com/HanHongChen/dp-udp/logger"
	"github.com/HanHongChen/dp-udp/model"
	"github.com/HanHongChen/dp-udp/tun"
	"github.com/HanHongChen/dp-udp/util"

	"github.com/cornelk/hashmap"
	"github.com/songgao/water"
)

const (
	WRITE_BATCH_MAX   = 1000                  // batch size
	WRITE_BATCH_DELAY = 10 * time.Millisecond // batch delay time
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
	writeToUdp1  chan []byte
	writeToUdp2  chan []byte

	writeToTun    chan []byte
	eliminateChan chan []byte
	// Client address mapping
	clientAddrs1 *hashmap.Map[string, *net.UDPAddr]
	clientAddrs2 *hashmap.Map[string, *net.UDPAddr]

	packetMap sync.Map // key: uint64, value: struct{}
	iperfMap  sync.Map

	// Thread-safe packet Eliminator
	count    uint64
	dupCount uint64
	dupSeq   uint64
	*logger.ServerLogger
}

func NewDpUdpServer(config *model.ServerConfig, serverLogger *logger.ServerLogger) *DpUdpServer {
	return &DpUdpServer{
		udpServer1: newUdpServer(config.ServerIE.UDP1ListenAddr, config.ServerIE.UDP1ListenPort),
		udpServer2: newUdpServer(config.ServerIE.UDP2ListenAddr, config.ServerIE.UDP2ListenPort),

		tunnelDeviceName:  config.ServerIE.TunnelDevice.Name,
		tunnelDeviceIP:    config.ServerIE.TunnelDevice.IP,
		tunnelRoutePrefix: config.ServerIE.TunnelDevice.RoutePrefix,

		readFromTun:  make(chan []byte, 10000),
		readFromUdp1: make(chan []byte, 10000),
		readFromUdp2: make(chan []byte, 10000),
		writeToUdp1:  make(chan []byte, 10000),
		writeToUdp2:  make(chan []byte, 10000),

		writeToTun:    make(chan []byte, 10000),
		eliminateChan: make(chan []byte, 10000),

		count:        0,
		dupCount:     0,
		dupSeq:       0,
		clientAddrs1: hashmap.New[string, *net.UDPAddr](),
		clientAddrs2: hashmap.New[string, *net.UDPAddr](),

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

	go s.readFromTunnelDevice(ctx)
	go s.dispatchFromTunnel(ctx)
	go s.sendToUdp1(ctx)
	go s.sendToUdp2(ctx)

	go s.readFromUdp1Connection(ctx)
	go s.readFromUdp2Connection(ctx)
	go s.writeToTunnelDevice(ctx)
	go s.startEliminatorWorkers(ctx)

	// go s.startRuntimeMonitor(ctx, "127.0.0.1:6060")

	s.ServerLog.Infof("DpUdpServer started successfully")
	return nil
}

// func (s *DpUdpServer) startRuntimeMonitor(ctx context.Context, addr string) {
// 	// pprof mux
// 	mux := http.NewServeMux()
// 	mux.HandleFunc("/debug/pprof/", pprof.Index)
// 	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
// 	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
// 	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
// 	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
// 	go func() {
// 		s.ServerLog.Infof("pprof listening on http://%s/debug/pprof/", addr)
// 		if err := http.ListenAndServe(addr, mux); err != nil {
// 			s.ServerLog.Errorf("pprof server error: %v", err)
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
// 			s.ServerLog.Debugf(
// 				"[MON] goroutines=%d alloc=%dKB gc=%d ch{rTun=%d, rU1=%d, rU2=%d, wU1=%d, wU2=%d, wTun=%d, elim=%d}",
// 				g, ms.Alloc/1024, ms.NumGC,
// 				len(s.readFromTun), len(s.readFromUdp1), len(s.readFromUdp2),
// 				len(s.writeToUdp1), len(s.writeToUdp2),
// 				len(s.writeToTun), len(s.eliminateChan),
// 			)
// 		}
// 	}
// }

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
	s.ServerLog.Infof("count = %d", atomic.LoadUint64(&s.count))
	s.ServerLog.Infof("dupCount = %d", atomic.LoadUint64(&s.dupCount))
	s.ServerLog.Infof("dupSeq = %d", atomic.LoadUint64(&s.dupSeq))
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
			// if isIperf, seq := util.IsIperf3Datagram(data); isIperf {
			// 	s.ServerLog.Warnf("iperf3 packet received seq %d", seq)
			// 	fmt.Printf("readFromTunnelDevice %d\n", seq)
			// }

			if !util.IsValidIPPacket(data) {
				s.ServerLog.Debugf("Invalid IP packet read from TUN device, skipping (size: %d)", n)
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

			data := make([]byte, n)
			copy(data, buffer[:n])
			// if isIperf, seq := util.IsIperf3Datagram(data); isIperf {
			// 	fmt.Printf("readFromUdp1Connection %d, size = %d\n", seq, n)
			// }

			if !util.IsValidIPPacket(data) {
				s.ServerLog.Debugf("Invalid IP packet read from UDP conn 1, skipping (size: %d)", n)
				continue
			}

			// Store client address for response routing
			clientKey := addr.String()
			s.clientAddrs1.Set(clientKey, addr)
			s.eliminateChan <- data

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
			data := make([]byte, n)
			copy(data, buffer[:n])
			// if isIperf, seq := util.IsIperf3Datagram(data); isIperf {
			// 	fmt.Printf("readFromUdp2Connection %d\n", seq)
			// }

			if !util.IsValidIPPacket(buffer) {
				s.ServerLog.Debugf("Invalid IP packet read from UDP conn 2, skipping (size: %d)", n)
				continue
			}

			// Store client address for response routing
			clientKey := addr.String()
			s.clientAddrs2.Set(clientKey, addr)
			s.eliminateChan <- data
		}
	}
}

func (s *DpUdpServer) writeToTunnelDevice(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():

			return
		case data := <-s.writeToTun:
			// if isIperf, seq := util.IsIperf3Datagram(data); isIperf {
			// 	fmt.Printf("writeToTunnelDevice %d\n", seq)
			// }
			atomic.AddUint64(&s.count, 1)
			if _, err := s.tunnelDevice.Write(data); err != nil {
				s.ServerLog.Errorf("Write to tunnel device failed: %v", err)
			}
		}
	}
}

func (s *DpUdpServer) startEliminatorWorkers(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case packet := <-s.eliminateChan:
			if s.packetEliminate(packet) {
				continue
			}
			s.writeToTun <- packet
		}
	}

}

// true: packet eliminated, false: packet passed
func (s *DpUdpServer) packetEliminate(packet []byte) bool {
	if isIperf, seq := util.IsIperf3Datagram(packet); isIperf {
		_, loaded := s.iperfMap.LoadOrStore(seq, struct{}{})
		// atomic.AddUint64(&s.dupCount, 1)

		if loaded {
			// fmt.Printf("%d 重複\n", seq)
			s.TunLog.Debugf("Eliminated iperf3 packet seq %d", seq)
			s.TunLog.Tracef("Eliminated iperf3 packet seq %d, %x", seq, packet)

			atomic.AddUint64(&s.dupSeq, 1)
			return true
		}
	} else {
		// non-iperf3 packet elimination based on hash
		h := sha512.Sum512(packet)
		_, loaded := s.packetMap.LoadOrStore(h, struct{}{})
		if loaded {
			s.TunLog.Debugf("Eliminated packet %d", h)
			s.TunLog.Tracef("Eliminated packet %d, %x", h, packet)

			return true
		}
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
			s.writeToUdp1 <- data
			s.writeToUdp2 <- data
		}
	}
}

func (s *DpUdpServer) sendToUdp1(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case data := <-s.writeToUdp1:
			s.clientAddrs1.Range(func(key string, addr *net.UDPAddr) bool {
				if err := s.udpServer1.write(data, addr); err != nil {
					s.ServerLog.Errorf("UDP 1 server write to %s failed: %v", addr, err)
				}
				return true
			})
		}
	}
}

func (s *DpUdpServer) sendToUdp2(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case data := <-s.writeToUdp2:
			s.clientAddrs2.Range(func(key string, addr *net.UDPAddr) bool {
				if err := s.udpServer2.write(data, addr); err != nil {
					s.ServerLog.Errorf("UDP 2 server write to %s failed: %v", addr, err)
				}
				return true
			})

		}
	}
}
