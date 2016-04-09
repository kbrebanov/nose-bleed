package protocols

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type TCPHeader struct {
	SourcePort     int      `json:"source_port"`
	DestPort       int      `json:"destination_port"`
	SequenceNumber int      `json:"sequence_number"`
	AckNumber      int      `json:"ack_number"`
	DataOffset     int      `json:"data_offset"`
	Flags          []string `json:"flags"`
	WindowSize     int      `json:"window_size"`
	Checksum       int      `json:"checksum"`
	Urgent         int      `json:"urgent_pointer"`
	//Options
}

// TCPParser parses a TCP segment header
func TCPParser(layer gopacket.Layer) TCPHeader {
	tcpFlags := make([]string, 0, 9)

	tcp := layer.(*layers.TCP)

	if tcp.FIN {
		tcpFlags = append(tcpFlags, "FIN")
	}
	if tcp.SYN {
		tcpFlags = append(tcpFlags, "SYN")
	}
	if tcp.RST {
		tcpFlags = append(tcpFlags, "RST")
	}
	if tcp.PSH {
		tcpFlags = append(tcpFlags, "PSH")
	}
	if tcp.ACK {
		tcpFlags = append(tcpFlags, "ACK")
	}
	if tcp.URG {
		tcpFlags = append(tcpFlags, "URG")
	}
	if tcp.ECE {
		tcpFlags = append(tcpFlags, "ECE")
	}
	if tcp.CWR {
		tcpFlags = append(tcpFlags, "CWR")
	}
	if tcp.NS {
		tcpFlags = append(tcpFlags, "NS")
	}

	tcpHeader := TCPHeader{
		SourcePort:     int(tcp.SrcPort),
		DestPort:       int(tcp.DstPort),
		SequenceNumber: int(tcp.Seq),
		AckNumber:      int(tcp.Ack),
		DataOffset:     int(tcp.DataOffset),
		Flags:          tcpFlags,
		WindowSize:     int(tcp.Window),
		Checksum:       int(tcp.Checksum),
		Urgent:         int(tcp.Urgent),
	}

	return tcpHeader
}
