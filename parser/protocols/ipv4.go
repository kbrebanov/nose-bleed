package protocols

import (
        "github.com/google/gopacket"
        "github.com/google/gopacket/layers"
)

type IPv4Header struct {
        Version int                 `json:"version"`
        IHL int                     `json:"header_length"`
        TOS int                     `json:"tos"`
        Length int                  `json:"total_length"`
        Identification int          `json:"identification"`
        Flags []string              `json:"flags"`
        FragOffset int              `json:"fragment_offset"`
        TTL int                     `json:"ttl"`
        Protocol string             `json:"protocol"`
        Checksum int                `json:"checksum"`
        SourceAddress string        `json:"source_address"`
        DestAddress string          `json:"destination_address"`
        //Options
}

func IPv4Parser(layer gopacket.Layer) IPv4Header {
        ipv4Flags := make([]string, 0, 3)

        ip, _ := layer.(*layers.IPv4)

        if ip.Flags == layers.IPv4EvilBit {
                ipv4Flags = append(ipv4Flags, "EB")
        }
        if ip.Flags == layers.IPv4DontFragment {
                ipv4Flags = append(ipv4Flags, "DF")
        }
        if ip.Flags == layers.IPv4MoreFragments {
                ipv4Flags = append(ipv4Flags, "MF")
        }

        ipv4Header := IPv4Header{
                Version: int(ip.Version),
                IHL: int(ip.IHL),
                TOS: int(ip.TOS),
                Length: int(ip.Length),
                Identification: int(ip.Id),
                Flags: ipv4Flags,
                FragOffset: int(ip.FragOffset),
                TTL: int(ip.TTL),
                Protocol: ip.Protocol.String(),
                Checksum: int(ip.Checksum),
                SourceAddress: ip.SrcIP.String(),
                DestAddress: ip.DstIP.String(),
        }
        return ipv4Header
}
