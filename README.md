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

- libpcap-dev

```bash
go get github.com/tools/godep

cd $GOPATH/src/github.com/kbrebanov/nose-bleed
godep restore
```

Build
=====

```bash
cd $GOPATH/src/github.com/kbrebanov/nose-bleed
go build
```

Usage
=====

Sending to standard output

(as root)
```bash
nose-bleed -device eth0 -snaplen 65535 -timeout 10s
```

Sending to a RabbitMQ exchange

1. Configure RabbitMQ settings in configuration file.
```json
{
  "rabbitmq": {
    "user": "guest",
    "password": "guest",
    "host": "localhost",
    "port": 5672,
    "exchange": "sniffer",
    "exchange_type": "fanout"
  }
}
```

2. (as root)
```bash
nose-bleed -config config.json -device eth0 -snaplen 65535 -timeout 10s
```

To do
=====
- [ ] Add tests
- [ ] Add comments/docs
- [x] Improve error handling
- [ ] Support more message brokers other than RabbitMQ
- [ ] Support RabbitMQ TLS connections
- [ ] Support specifying RabbitMQ exchange properties
- [x] Support BPFs
- [x] Godeps
- [ ] Handle IPv4 options
- [ ] Handle TCP options
- [ ] Support IPv6
