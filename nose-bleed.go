package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/kbrebanov/nose-bleed/sniffer"
)

const version string = "0.1.0"

func main() {
	device := flag.String("device", "eth0", "Device to sniff")
	snaplen := flag.Int("snaplen", 65535, "Snapshot length")
	promiscuous := flag.Bool("promiscuous", false, "Set promiscuous mode")
	timeout := flag.Duration("timeout", 30*time.Second, "Timeout")
	user := flag.String("user", "", "RabbitMQ user")
	passwd := flag.String("passwd", "", "RabbitMQ password")
	server := flag.String("server", "", "RabbitMQ server")
	exchange := flag.String("exchange", "", "RabbitMQ exchange name")
	filter := flag.String("filter", "", "Berkley Packet Filter (BPF)")
	showVersion := flag.Bool("version", false, "Show version")

	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		os.Exit(0)
	}

	// Start sniffing
	sniffer.Run(*device, int32(*snaplen), *promiscuous, *timeout,
		*user, *passwd, *server, *exchange, *filter)
}
