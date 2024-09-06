package main

import (
	"fmt"
	"log"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func ScanInterface(myInteface *Interface, targetInterface *Interface) []Interface {
	iface := myInteface.Name // Replace with your network interface name
	handle, err := pcap.OpenLive(iface, 65536, false, pcap.BlockForever)
	if err != nil {
		panic(err)
	}

	defer handle.Close()

	handle.SetBPFFilter("arp")

	go sendArpPackages(myInteface, handle)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	var interfaces []Interface

	go func() {
		seenIPs := make(map[string]bool)

		for p := range packetSource.Packets() {
			arp := p.Layer(layers.LayerTypeARP).(*layers.ARP)
			if arp.Operation == 2 {
				mac := net.HardwareAddr(arp.SourceHwAddress)

				log.Println("Response IP: Mac", arp.SourceProtAddress, mac.String(), arp.Payload)
			}

			// if arp.Operation == 1 {
			// 	mac := net.HardwareAddr(arp.SourceHwAddress)

			// 	log.Println("Request IP: Mac", arp.SourceProtAddress, mac.String(), arp.Payload)
			// }

			if seenIPs[string(arp.SourceProtAddress)] {
				continue
			}

			interfaces = append(interfaces, Interface{
				Name: getName(net.IP(arp.SourceProtAddress).String()),
				IP:   net.IP(arp.SourceProtAddress),
				MAC:  net.HardwareAddr(arp.SourceHwAddress),
			})

			seenIPs[string(arp.SourceProtAddress)] = true
		}
	}()

	time.Sleep(30 * time.Second)
	handle.Close()

	return interfaces
}

func getName(ip string) string {
	names, err := net.LookupAddr(ip)
	if err != nil {
		fmt.Println("Error:", err)
		return "Error"
	}

	// Print the hostname(s)
	for _, name := range names {
		log.Println("Name:", name)
	}

	return "Unknown"
}

func sendArpPackages(myInterface *Interface, pcapHadel *pcap.Handle) {

	time.Sleep(2 * time.Second)

	srcMAC, err := net.ParseMAC(myInterface.MAC.String()) // Replace with your MAC address
	if err != nil {
		panic(err)
	}

	srcIP := myInterface.IP // Replace with your IP address
	dstMAC, _ := net.ParseMAC("ff:ff:ff:ff:ff:ff")

	for i := 1; i <= 254; i++ {

		ipBytes := srcIP.To4()

		targetIP := net.IPv4(ipBytes[0], ipBytes[1], ipBytes[2], byte(i))

		// Skip self
		if ipBytes[3] == targetIP[3] {
			continue
		}

		etherLayer := &layers.Ethernet{
			SrcMAC:       srcMAC,
			DstMAC:       dstMAC,
			EthernetType: layers.EthernetTypeARP,
		}

		arpLayer := &layers.ARP{
			AddrType:          layers.LinkTypeEthernet,
			Protocol:          layers.EthernetTypeIPv4,
			HwAddressSize:     6,
			ProtAddressSize:   4,
			Operation:         layers.ARPRequest,
			SourceHwAddress:   srcMAC,
			SourceProtAddress: srcIP.To4(),
			DstHwAddress:      make([]byte, 6),
			DstProtAddress:    targetIP.To4(),
		}

		buffer := gopacket.NewSerializeBuffer()
		options := gopacket.SerializeOptions{}
		gopacket.SerializeLayers(buffer, options, etherLayer, arpLayer)
		outgoingPacket := buffer.Bytes()

		log.Println("Sending ARP packets to", targetIP.String())
		err = pcapHadel.WritePacketData(outgoingPacket)
		if err != nil {
			panic(err)
		}

		time.Sleep(100 * time.Millisecond)
	}
}
