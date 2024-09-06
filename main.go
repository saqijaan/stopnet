package main

import (
	"fmt"
	"log"
	"net"
)

func main() {

	intefaceScanner := Interface{}

	myInteface, error := intefaceScanner.GetNetworkInterface()

	if error != nil {
		fmt.Println("Error:", error)
		return
	}

	fmt.Println("Interface Name:", myInteface.Name)
	fmt.Println("Interface IP:", myInteface.IP)
	fmt.Println("Interface MAC:", myInteface.MAC)
	fmt.Println("Interface Gateway:", myInteface.Gateway)
	fmt.Println("Interface MASK:", myInteface.MASK)

	interfaces := ScanInterface(myInteface, &Interface{
		Name: myInteface.Name,
		IP:   myInteface.IP,
		MAC:  net.HardwareAddr{0x11, 0x11, 0x11, 0x11, 0x11, 0x11},
	})

	log.Println("Devices found:", len(interfaces))

	for _, iface := range interfaces {
		fmt.Println("Device Name:", iface.Name)
		fmt.Println("Device IP:", iface.IP)
		fmt.Println("Device MAC:", iface.MAC)
		fmt.Println("Device Gateway:", iface.Gateway)
		fmt.Println("Device MASK:", iface.MASK)
	}

	// myInterface := &Interface{
	// 	Name: "en0",
	// 	IP:   net.IPv4(192, 168, 100, 1),
	// 	MAC:  net.HardwareAddr{0x80, 0x65, 0x7c, 0xf0, 0x88, 0x0d}, //80:65:7c:f0:88:0d
	// }

	// targetInterface := &Interface{
	// 	Name: "en0",
	// 	IP:   net.IPv4(192, 168, 100, 11),
	// 	MAC:  net.HardwareAddr{0xf2, 0x75, 0xbc, 0xac, 0x44, 0x06}, //f2:75:bc:ac:44:06
	// }

	// SpoofInterface(myInterface, targetInterface)
}
