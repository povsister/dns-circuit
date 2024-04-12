package ospf

import (
	"encoding/binary"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/povsister/dns-circuit/ospf/packet"
)

var decOpts = gopacket.DecodeOptions{
	Lazy:                     false,
	NoCopy:                   true,
	SkipDecodeRecovery:       false,
	DecodeStreamsAsDatagrams: false,
}

func (i *Interface) doReadDispatch(pkt recvPkt) {
	dst := pkt.h.Dst
	if dst.String() != AllSPFRouters && !dst.Equal(i.Address.IP) {
		logWarn("Interface %s skipped 1 pkt processing causing its IPv4.Dst(%s)"+
			" is neither AllSPFRouter(%s) nor interface addr(%s)", i.c.ifi.Name, dst.String(), AllSPFRouters, i.Address.IP.String())
		return
	}
	ps := gopacket.NewPacket(pkt.p, layers.LayerTypeOSPF, decOpts)
	p := ps.Layer(layers.LayerTypeOSPF)
	if p == nil {
		err := ps.ErrorLayer().Error()
		logErr("Interface %s unexpected got nil OSPF parse result: %v", i.c.ifi.Name, err)
		return
	}
	l, ok := p.(*layers.OSPFv2)
	if !ok {
		logErr("Interface %s doReadDispatch expecting(*layers.OSPFv2) but got(%T)", i.c.ifi.Name, p)
		return
	}
	i.doParsedMsgProcessing(pkt.h, (*packet.LayerOSPFv2)(l))
}

func (i *Interface) queuePktForSend(pkt sendPkt) {
	select {
	case i.pendingSendPkt <- pkt:
	default:
		logWarn("Interface %s pending send pkt queue full. Dropped 1 %s pkt", pkt.p.GetType())
	}
}

func (i *Interface) doHello() (err error) {
	hello := &packet.OSPFv2Packet[packet.HelloPayloadV2]{
		OSPFv2: i.Area.ospfPktHeader(func(p *packet.LayerOSPFv2) {
			p.Type = layers.OSPFHello
		}),
		Content: packet.HelloPayloadV2{
			HelloPkg: layers.HelloPkg{
				RtrPriority:              i.RouterPriority,
				Options:                  2,
				HelloInterval:            i.HelloInterval,
				RouterDeadInterval:       i.RouterDeadInterval,
				DesignatedRouterID:       i.DR.Load(),
				BackupDesignatedRouterID: i.BDR.Load(),
			},
			NetworkMask: binary.BigEndian.Uint32(i.Address.Mask),
		},
	}
	i.nbMu.RLock()
	for _, nb := range i.Neighbors {
		hello.Content.NeighborID = append(hello.Content.NeighborID, nb.NeighborId)
	}
	i.nbMu.RUnlock()
	p := gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(p, gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}, hello)
	if err != nil {
		logErr("Interface %s err marshal %s->%s interval Hello Packet: %v", i.c.ifi.Name,
			i.Address.IP.String(), AllSPFRouters,
			err)
		return nil
	}
	_, err = i.c.WriteMulticastAllSPF(p.Bytes())
	if err != nil {
		logErr("Interface %s err send %s->%s interval Hello Packet: %v", i.c.ifi.Name,
			i.Address.IP.String(), AllSPFRouters,
			err)
	} else {
		//logDebug("Sent interval Hello Packet(%d) %s->%s via Interface %s:\n%+v", len(p.Bytes()),
		//	i.Address.IP.String(), AllSPFRouters,
		//	i.c.ifi.Name,
		//	hello)
	}
	return err
}

func (a *Area) ospfPktHeader(fn func(p *packet.LayerOSPFv2)) layers.OSPFv2 {
	ret := layers.OSPFv2{
		OSPF: layers.OSPF{
			Version:  2,
			Type:     0,
			RouterID: a.ins.RouterId,
			AreaID:   a.AreaId,
		},
		AuType:         0,
		Authentication: 0,
	}
	fn((*packet.LayerOSPFv2)(&ret))
	return ret
}
