package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"time"

	"github.com/kbrebanov/nose-bleed/sniffer"
)

const version string = "0.1.0"

type RabbitMQSettings struct {
	User         string  `json:"user"`
	Password     string  `json:"password"`
	Host         string  `json:"host"`
	Port         float64 `json:"port"`
	Exchange     string  `json:"exchange"`
	ExchangeType string  `json:"exchange_type"`
}

type Settings struct {
	RabbitMQ RabbitMQSettings `json:"rabbitmq,omitempty"`
}

func main() {
	// Set command line flags
	device := flag.String("device", "eth0", "Device to sniff")
	snaplen := flag.Int("snaplen", 65535, "Snapshot length")
	promiscuous := flag.Bool("promiscuous", false, "Set promiscuous mode")
	timeout := flag.Duration("timeout", 30*time.Second, "Timeout")
	filter := flag.String("filter", "", "Berkley Packet Filter (BPF)")
	showVersion := flag.Bool("version", false, "Show version")
	logFilePath := flag.String("log", "./nose-bleed.log", "Path to log file")
	configPath := flag.String("config", "settings.json", "Path to configuration file")

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

	// Get settings
	var settings Settings
	s, err := ioutil.ReadFile(*configPath)
	if err != nil {
		log.Fatal(err)
	}

	if err := json.Unmarshal(s, &settings); err != nil {
		log.Fatal(err)
	}

	// Start sniffing
	sniffer.Run(*device, int32(*snaplen), *promiscuous, *timeout,
		settings.RabbitMQ.User, settings.RabbitMQ.Password,
		fmt.Sprintf("%s:%d", settings.RabbitMQ.Host, int(settings.RabbitMQ.Port)),
		settings.RabbitMQ.Exchange, settings.RabbitMQ.ExchangeType, *filter)
}
