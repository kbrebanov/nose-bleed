package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"time"

	"github.com/kbrebanov/nose-bleed/parser"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/streadway/amqp"
)

const version string = "0.1.0"

// RabbitMQSettings is a structure for RabbitMQ settings
type RabbitMQSettings struct {
	User         string `json:"user"`
	Password     string `json:"password"`
	Host         string `json:"host"`
	Port         int    `json:"port"`
	Exchange     string `json:"exchange"`
	ExchangeType string `json:"exchange_type"`
}

// Settings is a structure for configuration settings
type Settings struct {
	RabbitMQ RabbitMQSettings `json:"rabbitmq,omitempty"`
}

// RabbitMQ error handler
func failOnError(err error, msg string) {
	if err != nil {
		log.Fatalf("%s: %s", msg, err)
	}
}

// sniff starts a live capture of network packets, parses and outputs
// the JSON results to either standard output or a RabbitMQ exchange.
func sniff(deviceName string, snapshotLen int32, promiscuous bool, timeout time.Duration,
	filter string, useRabbitMQ bool, settings *Settings) {

	var ch *amqp.Channel

	// Initialize msg queue
	if useRabbitMQ {
		conn, err := amqp.Dial(fmt.Sprintf("amqp://%s:%s@%s/", settings.RabbitMQ.User, settings.RabbitMQ.Password, fmt.Sprintf("%s:%d", settings.RabbitMQ.Host, settings.RabbitMQ.Port)))
		failOnError(err, "Failed to connect to RabbitMQ")
		defer conn.Close()

		// Create a channel
		ch, err = conn.Channel()
		failOnError(err, "Failed to open a channel")
		defer ch.Close()

		// Declare an exchange
		err = ch.ExchangeDeclare(settings.RabbitMQ.Exchange, settings.RabbitMQ.ExchangeType, true, false, false, false, nil)
		failOnError(err, "Failed to declare an exchange")
	}

	// Start a live capture
	handle, err := pcap.OpenLive(deviceName, snapshotLen, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Set filter
	if filter != "" {
		err = handle.SetBPFFilter(filter)
		if err != nil {
			log.Println(err)
		}
	}

	// Parse each packet
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		headers, err := parser.Parse(packet)
		if err != nil {
			log.Println(err)
		}

		if useRabbitMQ {
			b, err := json.Marshal(headers)
			if err != nil {
				log.Println(err)
				// Skip packet if JSON marshalling errors
				continue
			}
			// Send JSON to RabbitMQ exchange
			err = ch.Publish(settings.RabbitMQ.Exchange, "", false, false, amqp.Publishing{
				ContentType: "text/json",
				Body:        b,
			})
			failOnError(err, "Failed to publish a message")
		} else {
			// Pretty print JSON when sending to standard output
			b, err := json.MarshalIndent(headers, "", "  ")
			if err != nil {
				log.Println(err)
				// Skip packet if JSON marshalling errors
				continue
			}
			fmt.Println(string(b))
			fmt.Println()
		}
	}
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
	configPath := flag.String("config", "", "Path to configuration file in JSON format")

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
	settings := new(Settings)
	if *configPath != "" {
		s, err := ioutil.ReadFile(*configPath)
		if err != nil {
			log.Fatal(err)
		}

		if err := json.Unmarshal(s, settings); err != nil {
			log.Fatal(err)
		}
	}

	useRabbitMQ := false

	if settings.RabbitMQ.User != "" && settings.RabbitMQ.Password != "" && settings.RabbitMQ.Host != "" &&
		settings.RabbitMQ.Exchange != "" && settings.RabbitMQ.ExchangeType != "" {
		useRabbitMQ = true
	}

	// Start sniffing
	sniff(*device, int32(*snaplen), *promiscuous, *timeout, *filter, useRabbitMQ, settings)

}
