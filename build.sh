#!/bin/bash

# we need libpcap to build, use this to cross-compile
# docker run --rm -v "$PWD":/usr/src/myapp -w /usr/src/myapp -e GOOS=linux golang:1.4.2-cross /usr/src/myapp/build.sh

apt-get update && apt-get install -y libpcap-dev
go get github.com/constabulary/gb/...
go get github.com/google/gopacket
rm -rf bin
rm -rf pkg
gb build -v
