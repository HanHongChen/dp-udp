package model

type ClientConfig struct {
	ClientIE ClientIE `yaml:"client" valid:"required"`
	LoggerIE LoggerIE `yaml:"logger" valid:"required"`
}

type ClientIE struct {
	UDP1BindAddr   string `yaml:"udp1_bind_addr" valid:"required"`
	UDP1BindPort   int    `yaml:"udp1_bind_port" valid:"required"`
	UDP1RemoteAddr string `yaml:"udp1_remote_addr" valid:"required"`
	UDP1RemotePort int    `yaml:"udp1_remote_port" valid:"required"`
	UDP2BindAddr   string `yaml:"udp2_bind_addr" valid:"required"`
	UDP2BindPort   int    `yaml:"udp2_bind_port" valid:"required"`
	UDP2RemoteAddr string `yaml:"udp2_remote_addr" valid:"required"`
	UDP2RemotePort int    `yaml:"udp2_remote_port" valid:"required"`

	TunnelDevice TunnelDevice `yaml:"tunnel_device" valid:"required"`
}
