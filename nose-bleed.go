package main

import (
	"flag"
	"time"

	"github.com/kbrebanov/nose-bleed/sniffer"
)

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

	flag.Parse()

	// Start sniffing
	sniffer.Run(*device, int32(*snaplen), *promiscuous, *timeout,
		*user, *passwd, *server, *exchange, *filter)
}
