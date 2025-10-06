package client

import (
	"fmt"
	"net"
)

type udpClient struct {
	bindAddr   string
	bindPort   int
	remoteAddr string
	remotePort int
	conn       *net.UDPConn
}

func newUdpClient(bindAddr string, bindPort int, remoteAddr string, remotePort int) *udpClient {
	return &udpClient{
		bindAddr:   bindAddr,
		bindPort:   bindPort,
		remoteAddr: remoteAddr,
		remotePort: remotePort,
	}
}

func (c *udpClient) connect() error {
	// Resolve local bind address
	localAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(c.bindAddr, fmt.Sprintf("%d", c.bindPort)))
	if err != nil {
		return err
	}

	// Resolve remote address
	remoteAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(c.remoteAddr, fmt.Sprintf("%d", c.remotePort)))
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
