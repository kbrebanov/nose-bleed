package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/kbrebanov/nose-bleed/sniffer"
)

const version string = "0.1.0"

func main() {
	// Set command line flags
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
	logFilePath := flag.String("log", "./nose-bleed.log", "Path to log file")

	flag.Parse()

	// Show version and exit if version flag is set
	if *showVersion {
		fmt.Println(version)
		os.Exit(0)
	}

	// Configure logging
	logFile, err := os.OpenFile(*logFilePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer logFile.Close()
	log.SetOutput(logFile)

	// Start sniffing
	sniffer.Run(*device, int32(*snaplen), *promiscuous, *timeout,
		*user, *passwd, *server, *exchange, *filter)
}
