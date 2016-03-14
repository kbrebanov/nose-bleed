package main

import (
        "flag"
        "time"

        "github.com/kbrebanov/nose-bleed/sniffer"
)

func main() {
        device := flag.String("device", "eth0", "Device to sniff")
        snaplen := flag.Int("snaplen", 1024, "Snapshot length")
        promiscuous := flag.Bool("promiscuous", false, "Set promiscuous mode")
        timeout := flag.Duration("timeout", 30 * time.Second, "Timeout")

        flag.Parse()

        //sniffer.Run("en0", 1024, false, timeout)
        sniffer.Run(*device, int32(*snaplen), *promiscuous, *timeout)
}
