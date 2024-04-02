package ospf

import (
	"fmt"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/povsister/dns-circuit/ospf/packet"
)

type InstanceConfig struct {
	RouterId           uint32
	HelloInterval      uint16
	RouterDeadInterval uint32
	Network            *net.IPNet
	IfName             string
}

func NewInstance(c *InstanceConfig) *Instance {
	ins := &Instance{
		RouterId: c.RouterId,
		Backbone: NewArea(&AreaConfig{
			AreaId: 0,
			Address: &AreaAddress{
				Address: c.Network,
			},
			Options: CapOptions(0).SetBit(OptEbit),
		}),
	}
	ins.Backbone.AddInterface(&InterfaceConfig{
		Address:            c.Network,
		RouterPriority:     0,
		HelloInterval:      c.HelloInterval,
		RouterDeadInterval: c.RouterDeadInterval,
	})
	return ins
}

type Instance struct {
	RouterId uint32
	// The OSPF backbone area is responsible for the dissemination of
	//        inter-area routing information.
	Backbone *Area
	// Each one of the areas to which the router is connected has its
	//        own data structure.  This data structure describes the working
	//        of the basic OSPF algorithm.  Remember that each area runs a
	//        separate copy of the basic OSPF algorithm.
	// Not used yet
	Areas []*Area

	// These are routes to destinations external to the Autonomous
	//        System, that have been gained either through direct experience
	//        with another routing protocol (such as BGP), or through
	//        configuration information, or through a combination of the two
	//        (e.g., dynamic external information to be advertised by OSPF
	//        with configured metric). Any router having these external routes
	//        is called an AS boundary router.  These routes are advertised by
	//        the router into the OSPF routing domain via AS-external-LSAs.
	ExternalRoutes *RoutingTable

	// Part of the link-state database.  These have originated from the
	//        AS boundary routers.  They comprise routes to destinations
	//        external to the Autonomous System.  Note that, if the router is
	//        itself an AS boundary router, some of these AS-external-LSAs
	//        have been self-originated.
	ASExternalLSAs []*packet.V2ASExternalLSA
	// Derived from the link-state database.  Each entry in the routing
	//        table is indexed by a destination, and contains the
	//        destination's cost and a set of paths to use in forwarding
	//        packets to the destination. A path is described by its type and
	//        next hop.  For more information, see Section 11.
	RoutingTable *RoutingTable
}

func (r *Router) runIntervalTasks() {
	r.runHelloLoop()
	r.runRtDeadCheck()
}

func (r *Router) runRtDeadCheck() {
	r.ins.Area.tDead = time.NewTicker(time.Duration(r.ins.cfg.RouterDeadInterval) * time.Second)
	r.hasCompletelyShutdown.Add(1)
	go func() {
		for {
			select {
			case <-r.ctx.Done():
				r.ins.Area.tDead.Stop()
				r.hasCompletelyShutdown.Done()
				return
			case <-r.ins.Area.tDead.C:
				r.doDeadCheck()
			}
		}
	}()
}

func (r *Router) runHelloLoop() {
	r.ins.Area.tHello = time.NewTicker(time.Duration(r.ins.cfg.HelloInterval) * time.Second)
	r.hasCompletelyShutdown.Add(1)
	go func() {
		for {
			select {
			case <-r.ctx.Done():
				r.ins.Area.tHello.Stop()
				r.hasCompletelyShutdown.Done()
				return
			case <-r.ins.Area.tHello.C:
				r.doPeriodicHello()
			}
		}
	}()
}

func (r *Router) doPeriodicHello() {
	r.ins.Area.mu.RLock()
	defer r.ins.Area.mu.RUnlock()
	hello := packet.OSPFv2Packet[packet.HelloPayloadV2]{
		OSPFv2: layers.OSPFv2{
			OSPF: layers.OSPF{
				Version:  2,
				Type:     layers.OSPFHello,
				RouterID: r.ins.cfg.RouterId,
				AreaID:   r.ins.Area.Id,
			},
		},
		Content: packet.HelloPayloadV2{
			HelloPkg: layers.HelloPkg{
				RtrPriority:              0, // no DR or BDR
				Options:                  2,
				HelloInterval:            r.ins.cfg.HelloInterval,
				RouterDeadInterval:       r.ins.cfg.RouterDeadInterval,
				DesignatedRouterID:       r.ins.Area.DR,
				BackupDesignatedRouterID: r.ins.Area.BDR,
			},
			NetworkMask: 0xffffff00,
		},
	}
	for _, nb := range r.ins.Area.AdjNeighbors {
		hello.Content.NeighborID = append(hello.Content.NeighborID, nb.RtId)
	}
	p := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(p, gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}, &hello)
	if err != nil {
		fmt.Println("err Serialize Hello:", err)
	}

	fmt.Printf("Sent Hello pkt:\n%+v\n", hello)

	r.sendMulticast <- p.Bytes()
}

func (r *Router) doDeadCheck() {
	r.ins.Area.mu.Lock()
	defer r.ins.Area.mu.Unlock()
	var toDelete []uint32
	for _, n := range r.ins.Area.AdjNeighbors {
		if time.Since(time.Unix(n.LastSeen, 0)) >= time.Duration(r.ins.cfg.RouterDeadInterval)*time.Second {
			toDelete = append(toDelete, n.RtId)
		}
	}
	for _, d := range toDelete {
		delete(r.ins.Area.AdjNeighbors, d)
	}
}

func (r *Router) sendDD() {
	dd := packet.OSPFv2Packet[packet.DbDescPayload]{
		OSPFv2: layers.OSPFv2{
			OSPF: layers.OSPF{
				Version:  2,
				Type:     layers.OSPFDatabaseDescription,
				RouterID: r.ins.cfg.RouterId,
				AreaID:   r.ins.Area.Id,
			},
		},
		Content: packet.DbDescPayload{
			DbDescPkg: layers.DbDescPkg{
				Options:      2,
				InterfaceMTU: 1500,
				Flags:        5,
				DDSeqNumber:  0xf2a,
			},
			LSAinfo: []packet.LSAheader{
				{
					LSAge:       0,
					LSType:      layers.RouterLSAtypeV2,
					LinkStateID: r.ins.cfg.RouterId,
					AdvRouter:   r.ins.cfg.RouterId,
					LSSeqNumber: 0x80000001,
					LSOptions:   0,
				},
			},
		},
	}
}

// CapOptions The optional OSPF capabilities supported by the neighbor.
//
//		Learned during the Database Exchange process (see Section 10.6).
//		The neighbor's optional OSPF capabilities are also listed in its
//		Hello packets.  This enables received Hello Packets to be
//		rejected
//
//	   The OSPF Options field is present in OSPF Hello packets, Database
//	   Description packets and all LSAs.  The Options field enables OSPF
//	   routers to support (or not support) optional capabilities, and to
//	   communicate their capability level to other OSPF routers.  Through
//	   this mechanism routers of differing capabilities can be mixed within
//	   an OSPF routing domain.
//
//	   When used in Hello packets, the Options field allows a router to
//	   reject a neighbor because of a capability mismatch.  Alternatively,
//	   when capabilities are exchanged in Database Description packets a
//	   router can choose not to forward certain LSAs to a neighbor because
//	   of its reduced functionality.  Lastly, listing capabilities in LSAs
//	   allows routers to forward traffic around reduced functionality
//	   routers, by excluding them from parts of the routing table
//	   calculation.
//
//	   Five bits of the OSPF Options field have been assigned, although
//	   only one (the E-bit) is described completely by this memo. Each bit
//	   is described briefly below. Routers should reset (i.e.  clear)
//	   unrecognized bits in the Options field when sending Hello packets or
//	   Database Description packets and when originating LSAs. Conversely,
//	   routers encountering unrecognized Option bits in received Hello
//	   Packets, Database Description packets or LSAs should ignore the
//	   capability and process the packet/LSA normally.
//
//	                      +------------------------------------+
//	                      | * | * | DC | EA | N/P | MC | E | * |
//	                      +------------------------------------+
//
//	                            The Options field
type CapOptions uint8

const (
	// OptEbit This bit describes the way AS-external-LSAs are flooded, as
	//        described in Sections 3.6, 9.5, 10.8 and 12.1.2 of this memo.
	OptEbit = 1
	// OptMCbit This bit describes whether IP multicast datagrams are forwarded
	//        according to the specifications in [Ref18].
	OptMCbit = 2
	// OptNPbit This bit describes the handling of Type-7 LSAs, as specified in
	//        [Ref19].
	OptNPbit = 3
	// OptEAbit This bit describes the router's willingness to receive and
	//        forward External-Attributes-LSAs, as specified in [Ref20].
	OptEAbit = 4
	// OptDCbit This bit describes the router's handling of demand circuits, as
	//        specified in [Ref21].
	OptDCbit = 5
)

func (o CapOptions) SetBit(bits ...int) (ret CapOptions) {
	ret = o
	for _, bit := range bits {
		ret = ret.setBit(bit)
	}
	return
}

func (o CapOptions) setBit(bit int) CapOptions {
	return o | 1<<bit
}

func (o CapOptions) IsSet(bit int) bool {
	return o>>bit&1 == 1
}
