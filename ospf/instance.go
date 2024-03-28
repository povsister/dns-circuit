package ospf

import (
	"fmt"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/povsister/dns-circuit/ospf/packet"
)

type InstanceConfig struct {
	RouterId           uint32
	HelloInterval      uint16
	RouterDeadInterval uint32
}

type Instance struct {
	cfg  *InstanceConfig
	Area *Area // simply backbone
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

type Area struct {
	tHello *time.Ticker
	tDead  *time.Ticker
	Id     uint32

	mu           sync.RWMutex
	AdjNeighbors map[uint32]*KnownNeighbors
	DR           uint32
	BDR          uint32

	// List of area address ranges
	// In order to aggregate routing information at area boundaries,
	// area address ranges can be employed. Each address range is
	// specified by an [address,mask] pair and a status indication of
	// either Advertise or DoNotAdvertise
	Address []string
	// This router's interfaces connecting to the area.  A router
	// interface belongs to one and only one area (or the backbone).
	// For the backbone area this list includes all the virtual links.
	// A virtual link is identified by the Router ID of its other
	// endpoint; its cost is the cost of the shortest intra-area path
	// through the Transit area that exists between the two routers.
	Ifis []string
	// The shortest-path tree for the area, with this router itself as
	// root.  Derived from the collected router-LSAs and network-LSAs
	// by the Dijkstra algorithm (see Section 16.1).
	SPF *SPFTree
}

type KnownNeighbors struct {
	RtId     uint32
	LastSeen int64
}

type SPFTree struct {
}
