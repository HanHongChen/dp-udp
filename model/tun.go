package model

type TunnelDevice struct {
	Name        string `yaml:"name" valid:"required"`
	IP          string `yaml:"ip" valid:"required"`
	RoutePrefix string `yaml:"route_prefix" valid:"required"`
}
