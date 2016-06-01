nose-bleed
==========

Go DNS network packet sniffer

Description
===========

**nose-bleed** is a DNS network packet sniffer that outputs the parsed headers in JSON to standard output or to a RabbitMQ exchange.

It currently parses the following:

  - Ethernet
  - IPv4
  - IPv6
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
    "vhost": "",
    "tls": {
      "enabled": false,
      "ca_cert_file": "",
      "cert_file": "",
      "key_file": ""
    },
    "exchange": {
      "name": "sniffer",
      "type": "fanout",
      "durable": true,
      "auto_delete": false,
      "internal": false,
      "no_wait": false
    },
    "publish": {
      "key": "",
      "mandatory": false,
      "immediate": false
    }
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
- [x] Support RabbitMQ TLS connections
- [x] Support specifying RabbitMQ exchange properties
- [x] Support BPFs
- [x] Godeps
- [ ] Parse TCP options
- [x] Support IPv6
- [ ] Parse IPv6 hop by hop
