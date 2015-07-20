end all UDP traffic coming in on eth1, port 5060 to 10.10.10.10:5060:  udpreplay -i eth1 -f "udp and dst port 5060" -d "10.10.10.10:5060"
