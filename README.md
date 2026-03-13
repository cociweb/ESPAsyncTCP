# ESPAsyncTCP
[![Build Status](https://travis-ci.org/Adam5Wu/ESPAsyncTCP.svg?branch=adam5wu/master)](https://travis-ci.org/Adam5Wu/ESPAsyncTCP)
[![GitHub issues](https://img.shields.io/github/issues/Adam5Wu/ESPAsyncTCP.svg)](https://github.com/Adam5Wu/ESPAsyncTCP/issues)
[![GitHub forks](https://img.shields.io/github/forks/Adam5Wu/ESPAsyncTCP.svg)](https://github.com/Adam5Wu/ESPAsyncTCP/network)
[![License](https://img.shields.io/github/license/Adam5Wu/ESPAsyncTCP.svg)](./LICENSE.txt)

This is a fully asynchronous TCP library, aimed at enabling trouble-free, multi-connection network environment for Espressif's ESP8266 MCUs.

Modified to works with BearSSL port, which brings compatiblility with brokers using ECDSA certificates, supports SNI, and [maximum fragment length negotiation](https://tools.ietf.org/html/rfc6066#page-8).

* [Upstream Project](https://github.com/me-no-dev/ESPAsyncTCP-esp8266)
* [Modifications of this fork](MODIFICATIONS.md)
* Requires:
	- [ESP8266 Arduino Core fork](https://github.com/Adam5Wu/Arduino)
* Potentially interesting:
	- [ESP8266 BearSSL Port fork](https://github.com/Adam5Wu/bearssl-esp8266)
