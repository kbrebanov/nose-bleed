// Package sniffer implements a network packet sniffer.
package sniffer

import (
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/kbrebanov/nose-bleed/parser"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/streadway/amqp"
)

// Run starts a live capture of network packets, parses and outputs
// the JSON results to either standard output or a RabbitMQ exchange.
func Run(deviceName string, snapshotLen int32, promiscuous bool, timeout time.Duration,
	user string, passwd string, server string, exchange string) {
	var ch *amqp.Channel
	var USE_RABBITMQ = false

	// Initialize msg queue
	if user != "" && passwd != "" && server != "" && exchange != "" {
		conn, err := amqp.Dial(fmt.Sprintf("amqp://%s:%s@%s/", user, passwd, server))
		failOnError(err, "Failed to connect to RabbitMQ")
		defer conn.Close()

		ch, err = conn.Channel()
		failOnError(err, "Failed to open a channel")
		defer ch.Close()

		err = ch.ExchangeDeclare(exchange, "fanout", true, false, false, false, nil)
		failOnError(err, "Failed to declare an exchange")

		USE_RABBITMQ = true
	}

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
		if USE_RABBITMQ {
			b, err := json.Marshal(headers)
			if err != nil {
				panic(err)
			}
			err = ch.Publish(exchange, "", false, false, amqp.Publishing{
				ContentType: "text/json",
				Body:        b,
			})
			failOnError(err, "Failed to publish a message")
		} else {
			b, err := json.MarshalIndent(headers, "", "  ")
			if err != nil {
				panic(err)
			}
			fmt.Println(string(b))
			fmt.Println()
		}
	}
}

// RabbitMQ error handler
func failOnError(err error, msg string) {
	if err != nil {
		log.Fatalf("%s: %s", msg, err)
		panic(fmt.Sprintf("%s: %s", msg, err))
	}
}
