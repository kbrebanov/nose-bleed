/*
Package parser implements a library for parsing TCP/IP network packet headers.
*/
package parser

import (
	"github.com/kbrebanov/nose-bleed/parser/protocols"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Parse parses a packet header.
func Parse(packet gopacket.Packet) (map[string]interface{}, error) {
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

	// It this is an ICMPv6 packet, include it's header
	icmp6Layer := packet.Layer(layers.LayerTypeICMPv6)
	if icmp6Layer != nil {
		packetHeaders["icmpv6"] = protocols.ICMPv6Parser(icmp6Layer)
	}

	// If this is an IPv4 packet, include it's header
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		packetHeaders["ipv4"] = protocols.IPv4Parser(ipLayer)
	}

	// If this is an IPv6 packet, include it's header
	ip6Layer := packet.Layer(layers.LayerTypeIPv6)
	if ip6Layer != nil {
		packetHeaders["ipv6"] = protocols.IPv6Parser(ip6Layer)
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
		dns, err := protocols.DNSParser(dnsLayer)
		if err != nil {
			return nil, err
		}
		packetHeaders["dns"] = dns
	}

	return packetHeaders, nil
}
