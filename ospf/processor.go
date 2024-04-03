package ospf

import (
	"github.com/google/gopacket/layers"
	"golang.org/x/net/ipv4"

	"github.com/povsister/dns-circuit/ospf/packet"
)

func (i *Interface) doParsedMsgProcessing(h *ipv4.Header, op *packet.LayerOSPFv2) {
	switch op.Type {
	case layers.OSPFHello:
		hello, err := op.AsHello()
		if err != nil {
			logErr("unexpected non Hello: %v", err)
			return
		}
		i.Area.procHello(i, h, hello)
	case layers.OSPFDatabaseDescription:
		dbd, err := op.AsDbDescription()
		if err != nil {
			logErr("unexpected non DatabaseDesc: %v", err)
			return
		}
		i.Area.procDatabaseDesc(i, h, dbd)
	case layers.OSPFLinkStateRequest:
		lsr, err := op.AsLSRequest()
		if err != nil {
			logErr("unexpected non LSR: %v", err)
			return
		}
		i.Area.procLSR(i, h, lsr)
	case layers.OSPFLinkStateUpdate:
		lsu, err := op.AsLSUpdate()
		if err != nil {
			logErr("unexpected non LSU: %v", err)
			return
		}
		i.Area.procLSU(i, h, lsu)
	case layers.OSPFLinkStateAcknowledgment:
		lsack, err := op.AsLSAcknowledgment()
		if err != nil {
			logErr("unexpected non LSAck: %v", err)
			return
		}
		i.Area.procLSAck(i, h, lsack)
	default:
		logErr("unknown OSPF packet type: %v", op.Type)
	}
}

func (a *Area) procHello(i *Interface, h *ipv4.Header, hello *packet.OSPFv2Packet[packet.HelloPayloadV2]) {
	logDebug("Got OSPFv%d %s\nRouterId: %v AreaId:%v\n%+v\n",
		hello.Version, hello.Type, hello.RouterID, hello.AreaID, hello.Content)

	neighborId := hello.RouterID
	neighbor, ok := i.getNeighbor(neighborId)
	if !ok {
		neighbor = i.addNeighbor(h, hello)
	}
	neighbor.consumeEvent(NbEvHelloReceived)
	isMySelfSeen := false
	for _, seenNbs := range hello.Content.NeighborID {
		if seenNbs == a.ins.RouterId {
			isMySelfSeen = true
			break
		}
	}
	if isMySelfSeen {
		neighbor.consumeEvent(NbEv2WayReceived)
	}
}

func (a *Area) procDatabaseDesc(i *Interface, h *ipv4.Header, dbd *packet.OSPFv2Packet[packet.DbDescPayload]) {

}

func (a *Area) procLSR(i *Interface, h *ipv4.Header, lsr *packet.OSPFv2Packet[packet.LSRequestPayload]) {

}

func (a *Area) procLSU(i *Interface, h *ipv4.Header, lsu *packet.OSPFv2Packet[packet.LSUpdatePayload]) {

}

func (a *Area) procLSAck(i *Interface, h *ipv4.Header, lsack *packet.OSPFv2Packet[packet.LSAcknowledgementPayload]) {

}
