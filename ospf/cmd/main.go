package main

import (
	"fmt"
	"github.com/povsister/dns-circuit/ospf"
	"net"
)

func main() {
	ifi, err := net.InterfaceByName("en5")
	if err != nil {
		panic(err)
	}
	fmt.Println("Net Iface:", ifi)
	rc, err := ospf.ListenOSPFv2Multicast(ifi)
	if err != nil {
		panic(err)
	}
	defer rc.Close()
	fmt.Println("Raw Conn:", rc)
}
