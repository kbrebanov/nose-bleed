package sniffer

import (
        "encoding/json"
        "fmt"
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
                headers := parser.Parse(packet)
                //b, err := json.Marshal(headers)
                b, err := json.MarshalIndent(headers, "", "  ")
                if err != nil {
                        panic(err)
                }
                fmt.Println(string(b))
                fmt.Println()
        }
}
