package client

import (
	"fmt"
	"net"
)

type udpClient struct {
	dialAddr string
	dialPort int
	connAddr string
	connPort int
	conn     *net.UDPConn
}

func newUdpClient(dialAddr string, dialPort int, connAddr string, connPort int) *udpClient {
	return &udpClient{
		dialAddr: dialAddr,
		dialPort: dialPort,
		connAddr: connAddr,
		connPort: connPort,
	}
}

func (c *udpClient) connect() error {
	// Resolve local address
	localAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(c.dialAddr, fmt.Sprintf("%d", c.dialPort)))
	if err != nil {
		return err
	}

	// Resolve remote address
	remoteAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(c.connAddr, fmt.Sprintf("%d", c.connPort)))
	if err != nil {
		return err
	}

	// Create UDP connection
	conn, err := net.DialUDP("udp", localAddr, remoteAddr)
	if err != nil {
		return err
	}

	c.conn = conn
	return nil
}

func (c *udpClient) read(buffer []byte) (int, error) {
	return c.conn.Read(buffer)
}

func (c *udpClient) write(data []byte) error {
	_, err := c.conn.Write(data)
	return err
}

func (c *udpClient) close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}
