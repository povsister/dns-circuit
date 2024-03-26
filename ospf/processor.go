package ospf

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/povsister/dns-circuit/ospf/packet"
)

func (r *Router) runProcessLoop() {
	var (
		payload []byte
	)
	for {
		select {
		case <-r.ctx.Done():
			r.hasCompletelyShutdown.Done()
			return
		case payload = <-r.recvQ:
			r.doProcess(payload)
		}
	}
}

var decOpts = gopacket.DecodeOptions{
	Lazy:                     false,
	NoCopy:                   true,
	SkipDecodeRecovery:       false,
	DecodeStreamsAsDatagrams: false,
}

func (r *Router) doProcess(payload []byte) {
	fmt.Printf("Processing %d bytes\n", len(payload))
	ps := gopacket.NewPacket(payload, layers.LayerTypeOSPF, decOpts)
	p := ps.Layer(layers.LayerTypeOSPF)
	if p == nil {
		fmt.Println("nil OSPF layer")
		return
	}
	op, ok := p.(*layers.OSPFv2)
	if !ok {
		fmt.Println("unexpected non OSPFv2 msg")
		return
	}
	oop := (*packet.LayerOSPFv2)(op)
	hello, err := oop.AsHello()
	if err != nil {
		fmt.Println("unexpected non Hello:", err)
	}
	fmt.Printf("Got OSPFv%d %s\nRouterId: %v AreaId:%v\n%+v\n",
		hello.Version, hello.Type, hello.RouterID, hello.AreaID, hello.Content)

}
