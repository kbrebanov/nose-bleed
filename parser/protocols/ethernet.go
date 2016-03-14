package protocols

import (
        "github.com/google/gopacket"
        "github.com/google/gopacket/layers"
)

type EthernetHeader struct {
        SourceAddress string        `json:"source_address"`
        DestAddress string          `json:"destination_address"`
        Type string                 `json:"type"`
        Length int                  `json:"length"`
}

func EthernetParser(layer gopacket.Layer) EthernetHeader {
        ethernet, _ := layer.(*layers.Ethernet)
        ethernetHeader := EthernetHeader{
                SourceAddress: ethernet.SrcMAC.String(),
                DestAddress: ethernet.DstMAC.String(),
                Type: ethernet.EthernetType.String(),
                Length: int(ethernet.Length),
        }
        return ethernetHeader
}
