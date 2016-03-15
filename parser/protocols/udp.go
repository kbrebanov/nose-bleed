package protocols

import (
        "github.com/google/gopacket"
        "github.com/google/gopacket/layers"
)

type UDPHeader struct {
        SourcePort int              `json:"source_port"`
        DestPort int                `json:"destination_port"`
        Length int                  `json:"length"`
        Checksum int                `json:"checksum"`
}

func UDPParser(layer gopacket.Layer) UDPHeader {
        udp, _ := layer.(*layers.UDP)

        udpHeader := UDPHeader{
                SourcePort: int(udp.SrcPort),
                DestPort: int(udp.DstPort),
                Length: int(udp.Length),
                Checksum: int(udp.Checksum),
        }
        
        return udpHeader
}
