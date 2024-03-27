package ospf

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/net/ipv4"

	"github.com/povsister/dns-circuit/ospf/packet"
)

type ospfMsg struct {
	h *ipv4.Header
	p []byte // ospf packet
}

func (r *Router) runProcessLoop() {
	for {
		select {
		case <-r.ctx.Done():
			r.hasCompletelyShutdown.Done()
			return
		case msg := <-r.recvQ:
			r.doProcess(msg)
		}
	}
}

var decOpts = gopacket.DecodeOptions{
	Lazy:                     false,
	NoCopy:                   true,
	SkipDecodeRecovery:       false,
	DecodeStreamsAsDatagrams: false,
}

func (r *Router) doProcess(msg ospfMsg) {
	fmt.Printf("Processing %d bytes\n", len(msg.p))
	ps := gopacket.NewPacket(msg.p, layers.LayerTypeOSPF, decOpts)
	p := ps.Layer(layers.LayerTypeOSPF)
	if p == nil {
		fmt.Println("nil OSPF layer")
		return
	}
	l, ok := p.(*layers.OSPFv2)
	if !ok {
		fmt.Println("unexpected non OSPFv2 msg")
		return
	}

	op := (*packet.LayerOSPFv2)(l)
	switch op.Type {
	case layers.OSPFHello:
		hello, err := op.AsHello()
		if err != nil {
			fmt.Println("unexpected non Hello:", err)
			return
		}
		r.procHello(hello)
	case layers.OSPFDatabaseDescription:
		dbd, err := op.AsDbDescription()
		if err != nil {
			fmt.Println("unexpected non DatabaseDesc:", err)
			return
		}
		r.procDatabaseDesc(dbd)
	case layers.OSPFLinkStateRequest:
		lsr, err := op.AsLSRequest()
		if err != nil {
			fmt.Println("unexpected non LSR:", err)
			return
		}
		r.procLSR(lsr)
	case layers.OSPFLinkStateUpdate:
		lsu, err := op.AsLSUpdate()
		if err != nil {
			fmt.Println("unexpected non LSU:", err)
			return
		}
		r.procLSU(lsu)
	case layers.OSPFLinkStateAcknowledgment:
		lsack, err := op.AsLSAcknowledgment()
		if err != nil {
			fmt.Println("unexpected non LSAck:", err)
			return
		}
		r.procLSAck(lsack)
	default:
		fmt.Println("unknown OSPF packet type", op.Type)
	}
}

func (r *Router) procHello(hello *packet.OSPFv2Packet[packet.HelloPayloadV2]) {
	fmt.Printf("Got OSPFv%d %s\nRouterId: %v AreaId:%v\n%+v\n",
		hello.Version, hello.Type, hello.RouterID, hello.AreaID, hello.Content)
}

func (r *Router) procDatabaseDesc(dbd *packet.OSPFv2Packet[packet.DbDescPayload]) {

}

func (r *Router) procLSR(lsr *packet.OSPFv2Packet[packet.LSRequestPayload]) {

}

func (r *Router) procLSU(lsu *packet.OSPFv2Packet[packet.LSUpdatePayload]) {

}

func (r *Router) procLSAck(lsack *packet.OSPFv2Packet[packet.LSAcknowledgementPayload]) {

}
