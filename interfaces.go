package main

import (
	"fmt"
	"net"
)

type Interface struct {
	Name    string
	IP      net.IP
	MAC     net.HardwareAddr
	Gateway string
	MASK    string
}

func (iface *Interface) GetNetworkInterface() (*Interface, error) {
	// Get a list of all network interfaces
	interfaces, err := net.Interfaces()
	if err != nil {
		fmt.Println("Error:", err)
		return nil, err
	}

	for _, iface := range interfaces {
		// Skip down or loopback interfaces
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			fmt.Println("Error getting addresses:", err)
			continue
		}

		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok || ipNet.IP.IsLoopback() {
				continue
			}

			// Check if the IP address is IPv4 and not a loopback address
			ipv4 := ipNet.IP.To4()
			if ipv4 == nil {
				continue
			}

			return &Interface{
				Name:    iface.Name,
				IP:      ipv4,
				MAC:     iface.HardwareAddr,
				Gateway: "",
				MASK:    ipv4.Mask(ipNet.Mask).To16().String(),
			}, nil
		}
	}

	return nil, fmt.Errorf("no active network interface found")
}
