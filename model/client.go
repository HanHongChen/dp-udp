package model

type ClientConfig struct {
	ClientIE ClientIE `yaml:"client" valid:"required"`
	LoggerIE LoggerIE `yaml:"logger" valid:"required"`
}

type ClientIE struct {
	UDP1DialAddr string `yaml:"udp1_dial_addr" valid:"required"`
	UDP1DialPort int    `yaml:"udp1_dial_port" valid:"required"`
	UDP1ConnAddr string `yaml:"udp1_conn_addr" valid:"required"`
	UDP1ConnPort int    `yaml:"udp1_conn_port" valid:"required"`
	UDP2DialAddr string `yaml:"udp2_dial_addr" valid:"required"`
	UDP2DialPort int    `yaml:"udp2_dial_port" valid:"required"`
	UDP2ConnAddr string `yaml:"udp2_conn_addr" valid:"required"`
	UDP2ConnPort int    `yaml:"udp2_conn_port" valid:"required"`

	TunnelDevice TunnelDevice `yaml:"tunnel_device" valid:"required"`
}
