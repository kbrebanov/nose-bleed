package protocols

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// ICMPv6Header represents and ICMPv6 header
type ICMPv6Header struct {
	Type     int `json:"type"`
	Code     int `json:"code"`
	Checksum int `json:"checksum"`
	//TypeBytes
}

// ICMPv6Parser parses an ICMPv6 header
func ICMPv6Parser(layer gopacket.Layer) ICMPv6Header {
	icmpv6 := layer.(*layers.ICMPv6)

	icmpv6Header := ICMPv6Header{
		Type:     int(icmpv6.TypeCode.Type()),
		Code:     int(icmpv6.TypeCode.Code()),
		Checksum: int(icmpv6.Checksum),
	}

	return icmpv6Header
}
