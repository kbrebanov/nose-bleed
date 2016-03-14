package sniffer

import (
        "log"
        "time"

        "github.com/kbrebanov/nose-bleed/parser"

        "github.com/google/gopacket"
        "github.com/google/gopacket/pcap"
)

func Run(deviceName string, snapshotLen int32, promiscuous bool, timeout time.Duration) {
        // Start a live capture
        handle, err := pcap.OpenLive(deviceName, snapshotLen, promiscuous, timeout)
        if err != nil {
                log.Fatal(err)
        }
        defer handle.Close()

        // Parse each packet
        packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
        for packet := range packetSource.Packets() {
                parser.Parse(packet)
        }
}
