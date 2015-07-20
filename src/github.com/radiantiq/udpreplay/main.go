package main

import (
	"flag"
	"log"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var iface = flag.String("i", "eth0", "Interface to get packets from")
var snaplen = flag.Int("s", 1600, "SnapLen for pcap packet capture")
var filter = flag.String("f", "udp and dst port 5060", "filter for pcap")
var dstHostPort = flag.String("d", "", "Destination host:port to replay traffic to")

func main() {
	flag.Parse()
	handle, err := pcap.OpenLive(*iface, int32(*snaplen), true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}

	if err := handle.SetBPFFilter(*filter); err != nil {
		log.Fatal(err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		log.Println(packet.String())
		if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
			udp, _ := udpLayer.(*layers.UDP)
			fwdSIPPacket(udp.BaseLayer.Payload)
		}
	}
}

func fwdSIPPacket(payload []byte) {
	c, err := net.ListenPacket("udp", ":0")
	if err != nil {
		log.Fatal(err)
	}
	defer c.Close()

	dst, err := net.ResolveUDPAddr("udp", *dstHostPort)
	if err != nil {
		log.Fatal(err)
	}

	_, err = c.WriteTo(payload, dst)
	if err != nil {
		log.Fatal(err)
	}
}
