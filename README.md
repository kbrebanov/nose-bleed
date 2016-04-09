nose-bleed
==========

Go network packet sniffer

Description
===========

**nose-bleed** is a network packet sniffer that outputs the parsed headers in JSON to standard
output or to a RabbitMQ exchange.

It currently parses the following:

  - Ethernet
  - ICMPv4
  - IPv4
  - UDP
  - TCP
  - DNS

Dependencies
============

```
go get github.com/google/gopacket
go get github.com/streadway/amqp
```

Usage
=====

Sending to standard output

(as root)
```bash
nose-bleed -device eth0 -snaplen 65535 -promiscuous -timeout 10s
```

Sending to a RabbitMQ exchange

(as root)
```bash
nose-bleed -device eth0 -snaplen 65535 -promiscuous -timeout 10s -user guest -passwd guest -server localhost:5672 -exchange packets
```

To do
=====
- [ ] Add tests
- [ ] Add comments/docs
- [ ] Improve error handling
- [ ] Support more message brokers other than RabbitMQ
- [ ] Support RabbitMQ TLS connections
- [ ] Support specifying RabbitMQ exchange properties
- [ ] Support BPFs
