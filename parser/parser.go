/*
Package parser implements a library for parsing TCP/IP network packet headers.
*/
package parser

import (
	"github.com/kbrebanov/nose-bleed/parser/protocols"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type PacketLayers struct {
	EthernetLayer layers.Ethernet
	IPv4Layer     layers.IPv4
	IPv6Layer     layers.IPv6
	UDPLayer      layers.UDP
	TCPLayer      layers.TCP
	DNSLayer      layers.DNS
}

// Parse parses a packet header.
func Parse(packetData []byte, packetMetaData gopacket.CaptureInfo, decoder *gopacket.DecodingLayerParser, packetLayers *PacketLayers) (map[string]interface{}, error) {
	packetHeaders := make(map[string]interface{})

	// Include packet timestamp
	packetHeaders["timestamp"] = (&packetMetaData.Timestamp).String()

	decodedLayers := []gopacket.LayerType{}

	err := decoder.DecodeLayers(packetData, &decodedLayers)
	if err != nil {
		return nil, err
	}

	for _, layerType := range decodedLayers {
		switch layerType {
		case layers.LayerTypeEthernet:
			packetHeaders["ethernet"] = protocols.EthernetParser(packetLayers.EthernetLayer)
		case layers.LayerTypeIPv4:
			packetHeaders["ipv4"] = protocols.IPv4Parser(packetLayers.IPv4Layer)
		case layers.LayerTypeIPv6:
			packetHeaders["ipv6"] = protocols.IPv6Parser(packetLayers.IPv6Layer)
		case layers.LayerTypeUDP:
			packetHeaders["udp"] = protocols.UDPParser(packetLayers.UDPLayer)
		case layers.LayerTypeTCP:
			packetHeaders["tcp"] = protocols.TCPParser(packetLayers.TCPLayer)
		case layers.LayerTypeDNS:
			dns, err := protocols.DNSParser(packetLayers.DNSLayer)
			if err != nil {
				return nil, err
			}
			packetHeaders["dns"] = dns
		}
	}

	return packetHeaders, nil
}
