package model

type ServerConfig struct {
	ServerIE ServerIE `yaml:"server" valid:"required"`
	LoggerIE LoggerIE `yaml:"logger" valid:"required"`
}

type ServerIE struct {
	UDP1ListenAddr string `yaml:"udp1_listen_addr" valid:"required"`
	UDP1ListenPort int    `yaml:"udp1_listen_port" valid:"required"`
	UDP2ListenAddr string `yaml:"udp2_listen_addr" valid:"required"`
	UDP2ListenPort int    `yaml:"udp2_listen_port" valid:"required"`

	TunnelDevice TunnelDevice `yaml:"tunnel_device" valid:"required"`
	Redundant    bool         `yaml:"redundant" valid:"required"`
}
