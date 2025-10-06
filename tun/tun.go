package tun

import (
	"fmt"
	"os/exec"
	"net"
	"strconv"


	"github.com/songgao/water"
)

func deriveCIDR(ipStr string, prefix string) (string, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "", fmt.Errorf("invalid IP: %s", ipStr)
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return "", fmt.Errorf("not an IPv4 address: %s", ipStr)
	}
	prefixInt, err := strconv.Atoi(prefix)
    if err != nil {
        return "", fmt.Errorf("invalid prefix (not a number): %s", prefix)
    }

	mask := net.CIDRMask(prefixInt, 32)
	network := ip4.Mask(mask)
	return fmt.Sprintf("%s", network.String()), nil
}

// CreateTunnelDevice creates and configures a tunnel device - alias for BringUpUeTunnelDevice
func CreateTunnelDevice(ueTunnelDeviceName string, ip string, routePrefix string) (*water.Interface, error) {
	return BringUpUeTunnelDevice(ueTunnelDeviceName, ip, routePrefix)
}

func BringUpUeTunnelDevice(ueTunnelDeviceName string, ip string, routePrefix string) (*water.Interface, error) {
	tunCfg := water.Config{
		DeviceType: water.TUN,
	}
	tunCfg.Name = ueTunnelDeviceName

	tun, err := water.New(tunCfg)
	if err != nil {
		return nil, fmt.Errorf("error creating tunnel device: %v", err)
	}
	
	// Check if the device was actually created
	fmt.Printf("TUN device created with name: %s\n", tun.Name())
	route, err := deriveCIDR(ip, routePrefix)
	if err != nil {
		return nil, fmt.Errorf("error deriveCIDR: %v", err)
	}
	// return nil, fmt.Errorf("%s, tun", route)
	// Use the actual device name from the created TUN interface
	actualDevName := tun.Name()
	cmds := [][]string{
		{"ip", "addr", "add", fmt.Sprintf("%s/32", ip), "dev", actualDevName},
		{"ip", "link", "set", "dev", actualDevName, "up"},
		// {"ip", "route", "add", "default", "via", ip},
		{"ip", "route", "add", fmt.Sprintf("%s/%s", route, routePrefix), "dev", actualDevName},
	}

	for i, cmd := range cmds {
		fmt.Printf("Executing command %d: %v\n", i, cmd)
		output, err := exec.Command(cmd[0], cmd[1:]...).CombinedOutput()
		if err != nil {
			return nil, fmt.Errorf("error executing command %v: %v, output: %s", cmd, err, string(output))
		}
		fmt.Printf("Command %d completed successfully\n", i)
	}

	return tun, nil
}

func BringDownUeTunnelDevice(ueTunnelDeviceName string, ip string, routePrefix string) error {
	route, err := deriveCIDR(ip, routePrefix)
	if err != nil {
		return fmt.Errorf("error deriveCIDR: %v", err)
	}
	cmds := [][]string{
		{"ip", "route", "del", fmt.Sprintf("%s/%s", route, routePrefix), "dev", ueTunnelDeviceName},
		{"ip", "addr", "flush", "dev", ueTunnelDeviceName},
		{"ip", "link", "set", "dev", ueTunnelDeviceName, "down"},
	}

	for i, cmd := range cmds {
		fmt.Printf("Cleanup command %d: %v\n", i, cmd)
		output, err := exec.Command(cmd[0], cmd[1:]...).CombinedOutput()
		if err != nil {
			// Some cleanup commands might fail if the device/route doesn't exist
			// Log the error but continue with other cleanup commands
			fmt.Printf("Cleanup command %d failed (continuing): %v, output: %s\n", i, err, string(output))
		} else {
			fmt.Printf("Cleanup command %d completed successfully\n", i)
		}
	}

	return nil
}
