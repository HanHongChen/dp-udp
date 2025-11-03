package server

import (
	"fmt"
	"net"
)

type udpServer struct {
	listenAddr string
	listenPort int
	conn       *net.UDPConn
}

func newUdpServer(listenAddr string, listenPort int) *udpServer {
	return &udpServer{
		listenAddr: listenAddr,
		listenPort: listenPort,
	}
}

func tuneUDP(c *net.UDPConn) {
	c.SetReadBuffer(64 << 20) // 16 MiB
	c.SetWriteBuffer(64 << 20)
}

func (s *udpServer) listen() error {
	addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(s.listenAddr, fmt.Sprintf("%d", s.listenPort)))
	if err != nil {
		return err
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}

	s.conn = conn
	tuneUDP(s.conn)
	return nil
}

func (s *udpServer) read(buffer []byte) (int, *net.UDPAddr, error) {
	return s.conn.ReadFromUDP(buffer)
}

func (s *udpServer) write(data []byte, addr *net.UDPAddr) error {
	_, err := s.conn.WriteToUDP(data, addr)
	return err
}

func (s *udpServer) close() error {
	if s.conn != nil {
		return s.conn.Close()
	}
	return nil
}
