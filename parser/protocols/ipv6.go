package protocols

import "github.com/google/gopacket/layers"

type IPv6Header struct {
	Version       int    `json:"version"`
	TrafficClass  int    `json:"traffic_class"`
	FlowLabel     int    `json:"flow_label"`
	Length        int    `json:"total_length"`
	NextHeader    string `json:"next_header"`
	HopLimit      int    `json:"hop_limit"`
	SourceAddress string `json:"source_address"`
	DestAddress   string `json:"destination_address"`
	//HopByHop
}

// IPv6Parser parses an IPv6 packet header
func IPv6Parser(ipv6 layers.IPv6) IPv6Header {

	ipv6Header := IPv6Header{
		Version:       int(ipv6.Version),
		TrafficClass:  int(ipv6.TrafficClass),
		FlowLabel:     int(ipv6.FlowLabel),
		Length:        int(ipv6.Length),
		NextHeader:    ipv6.NextHeader.String(),
		HopLimit:      int(ipv6.HopLimit),
		SourceAddress: ipv6.SrcIP.String(),
		DestAddress:   ipv6.DstIP.String(),
	}

	return ipv6Header
}
