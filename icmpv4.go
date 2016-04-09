package main

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type ICMPv4Header struct {
	Type           int `json:"type"`
	Code           int `json:"code"`
	Checksum       int `json:"checksum"`
	Identification int `json:"identification"`
	SequenceNumber int `json:"sequence_number"`
}

// ICMPv4Parser parses an ICMPv4 header
func ICMPv4Parser(layer gopacket.Layer) ICMPv4Header {
	icmp := layer.(*layers.ICMPv4)

	icmpv4Header := ICMPv4Header{
		Type:           int(icmp.TypeCode.Type()),
		Code:           int(icmp.TypeCode.Code()),
		Checksum:       int(icmp.Checksum),
		Identification: int(icmp.Id),
		SequenceNumber: int(icmp.Seq),
	}

	return icmpv4Header
}
