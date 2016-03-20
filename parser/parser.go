// Package parser implements a library for parsing TCP/IP network packet headers.
package parser

import (
	"github.com/kbrebanov/nose-bleed/parser/protocols"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Parse parses a packet header.
func Parse(packet gopacket.Packet) map[string]interface{} {
	packetHeaders := make(map[string]interface{})

	metaData := packet.Metadata()

	// Include packet timestamp
	packetHeaders["timestamp"] = (&metaData.CaptureInfo.Timestamp).String()

	// If this packet has an Ethernet frame, include it's header
	ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethernetLayer != nil {
		packetHeaders["ethernet"] = protocols.EthernetParser(ethernetLayer)
	}

	// If this is an ICMP packet, include it's header
	icmpLayer := packet.Layer(layers.LayerTypeICMPv4)
	if icmpLayer != nil {
		packetHeaders["icmpv4"] = protocols.ICMPv4Parser(icmpLayer)
	}

	// If this is an IPv4 packet, include it's header
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		packetHeaders["ipv4"] = protocols.IPv4Parser(ipLayer)
	}

	// If this is a UDP datagram, include it's header
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer != nil {
		packetHeaders["udp"] = protocols.UDPParser(udpLayer)
	}

	// If this is a TCP segment, include it's header
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		packetHeaders["tcp"] = protocols.TCPParser(tcpLayer)
	}

	// If this packet has a DNS payload, include it's data
	dnsLayer := packet.Layer(layers.LayerTypeDNS)
	if dnsLayer != nil {
		packetHeaders["dns"] = protocols.DNSParser(dnsLayer)
	}

	return packetHeaders
}
