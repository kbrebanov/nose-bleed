package main

import (
	"crypto/tls"
	"crypto/x509"
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

const version string = "0.4.0"

// RabbitMQPublishSettings is a structure for RabbitMQ publish settings
type RabbitMQPublishSettings struct {
	Key       string `json:"key"`
	Mandatory bool   `json:"mandatory"`
	Immediate bool   `json:"immediate"`
}

// RabbitMQExchangeSettings is a structure for RabbitMQ exchange settings
type RabbitMQExchangeSettings struct {
	Name       string `json:"name"`
	Type       string `json:"type"`
	Durable    bool   `json:"durable"`
	AutoDelete bool   `json:"auto_delete"`
	Internal   bool   `json:"internal"`
	NoWait     bool   `json:"no_wait"`
}

// RabbitMQTLSSettings is a structure for RabbitMQ TLS settings
type RabbitMQTLSSettings struct {
	Enabled    bool   `json:"enabled"`
	CACertFile string `json:"ca_cert_file"`
	CertFile   string `json:"cert_file"`
	KeyFile    string `json:"key_file"`
}

// RabbitMQSettings is a structure for RabbitMQ settings
type RabbitMQSettings struct {
	User     string                   `json:"user"`
	Password string                   `json:"password"`
	Host     string                   `json:"host"`
	Port     int                      `json:"port"`
	TLS      RabbitMQTLSSettings      `json:"tls"`
	Exchange RabbitMQExchangeSettings `json:"exchange"`
	Publish  RabbitMQPublishSettings  `json:"publish"`
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
func sniff(deviceName string, snapshotLen int, promiscuous bool, timeout time.Duration,
	filter string, settings *Settings) {

	var ch *amqp.Channel
	var conn *amqp.Connection

	useRabbitMQ := false

	if settings.RabbitMQ.User != "" && settings.RabbitMQ.Password != "" && settings.RabbitMQ.Host != "" &&
		settings.RabbitMQ.Exchange.Name != "" && settings.RabbitMQ.Exchange.Type != "" {
		useRabbitMQ = true
	}

	// Initialize msg queue
	if useRabbitMQ {
		if settings.RabbitMQ.TLS.Enabled {
			tlsConfig := new(tls.Config)
			tlsConfig.RootCAs = x509.NewCertPool()

			if ca, err := ioutil.ReadFile(settings.RabbitMQ.TLS.CACertFile); err == nil {
				tlsConfig.RootCAs.AppendCertsFromPEM(ca)
			}

			if cert, err := tls.LoadX509KeyPair(settings.RabbitMQ.TLS.CertFile, settings.RabbitMQ.TLS.KeyFile); err == nil {
				tlsConfig.Certificates = append(tlsConfig.Certificates, cert)
			}

			var err error
			conn, err = amqp.DialTLS(
				fmt.Sprintf("amqps://%s:%s@%s/",
					settings.RabbitMQ.User,
					settings.RabbitMQ.Password,
					fmt.Sprintf("%s:%d", settings.RabbitMQ.Host, settings.RabbitMQ.Port)),
				tlsConfig)
			failOnError(err, "Failed to connect to RabbitMQ using TLS")
			defer conn.Close()
		} else {
			var err error
			conn, err = amqp.Dial(
				fmt.Sprintf("amqp://%s:%s@%s/",
					settings.RabbitMQ.User,
					settings.RabbitMQ.Password,
					fmt.Sprintf("%s:%d", settings.RabbitMQ.Host, settings.RabbitMQ.Port)))
			failOnError(err, "Failed to connect to RabbitMQ")
			defer conn.Close()
		}

		var err error

		// Create a channel
		ch, err = conn.Channel()
		failOnError(err, "Failed to open a channel")
		defer ch.Close()

		// Declare an exchange
		err = ch.ExchangeDeclare(
			settings.RabbitMQ.Exchange.Name,
			settings.RabbitMQ.Exchange.Type,
			settings.RabbitMQ.Exchange.Durable,
			settings.RabbitMQ.Exchange.AutoDelete,
			settings.RabbitMQ.Exchange.Internal,
			settings.RabbitMQ.Exchange.NoWait,
			nil)
		failOnError(err, "Failed to declare an exchange")
	}

	// Start a live capture
	handle, err := pcap.OpenLive(deviceName, int32(snapshotLen), promiscuous, timeout)
	if err != nil {
		log.Fatalln("Failed to start packet capture:", err)
	}
	defer handle.Close()

	// Set filter
	if filter != "" {
		err = handle.SetBPFFilter(filter)
		if err != nil {
			log.Println("Failed to set BPF:", err)
		}
	}

	// Parse each packet
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		headers, err := parser.Parse(packet)
		if err != nil {
			log.Println("Failed to parse packet:", err)
		}

		if useRabbitMQ {
			b, err := json.Marshal(headers)
			if err != nil {
				log.Println("Failed to marshal packet to JSON:", err)
				// Skip packet if JSON marshalling errors
				continue
			}
			// Send JSON to RabbitMQ exchange
			err = ch.Publish(
				settings.RabbitMQ.Exchange.Name,
				settings.RabbitMQ.Publish.Key,
				settings.RabbitMQ.Publish.Mandatory,
				settings.RabbitMQ.Publish.Immediate,
				amqp.Publishing{
					ContentType: "text/json",
					Body:        b,
				})
			failOnError(err, "Failed to publish a message")
		} else {
			// Pretty print JSON when sending to standard output
			b, err := json.MarshalIndent(headers, "", "  ")
			if err != nil {
				log.Println("Failed to marshal packet to JSON:", err)
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
		fmt.Fprintln(os.Stderr, "Failed to open log file:", err)
		os.Exit(1)
	}
	defer logFile.Close()
	log.SetOutput(logFile)

	// Get settings
	settings := new(Settings)
	if *configPath != "" {
		s, err := ioutil.ReadFile(*configPath)
		if err != nil {
			log.Fatalln("Failed to get settings:", err)
		}

		if err := json.Unmarshal(s, settings); err != nil {
			log.Fatalln("Failed to unmarshal JSON settings:", err)
		}
	}

	// Start sniffing
	sniff(*device, *snaplen, *promiscuous, *timeout, *filter, settings)

}
