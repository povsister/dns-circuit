package main

import (
	"flag"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/povsister/dns-circuit/ospf"
)

var (
	ifName = flag.String("ifname", "", "net if name")
	laddr  = flag.String("laddr", "", "local addr")
	rtid   = flag.String("rtid", "", "router id")
)

func main() {
	flag.Parse()
	if len(*ifName) <= 0 {
		panic("empty ifName")
	}
	if len(*laddr) <= 0 {
		panic("empty laddr")
	}
	if pip := net.ParseIP(*laddr); pip == nil {
		panic("invalid laddr")
	} else if pip4 := pip.To4(); pip4 == nil {
		panic("laddr is not a IPv4 addr")
	}
	if pip := net.ParseIP(*rtid); pip == nil {
		panic("invalid rtid")
	} else if pip4 := pip.To4(); pip4 == nil {
		panic("rtid is not a IPv4 addr")
	}

	rt, err := ospf.NewRouter(*ifName, *laddr, *rtid)
	if err != nil {
		panic(err)
	}
	//rt.StartEcho()

	stopC := make(chan os.Signal)
	go func() {
		signal.Notify(stopC, syscall.SIGQUIT, syscall.SIGTERM, syscall.SIGINT)
	}()
	<-stopC
	rt.Close()
}
