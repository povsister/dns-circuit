package ospf

import (
	"context"
	"net"

	"github.com/povsister/dns-circuit/ospf/packet"
)

type InstanceConfig struct {
	RouterId           uint32
	HelloInterval      uint16
	RouterDeadInterval uint32
	Network            *net.IPNet
	IfName             string
}

func NewInstance(ctx context.Context, c *InstanceConfig) *Instance {
	ins := &Instance{
		RouterId: c.RouterId,
	}
	ins.Backbone = NewArea(ctx, &AreaConfig{
		Instance: ins,
		AreaId:   0,
		Address: &AreaAddress{
			Address: c.Network,
		},
		Options: packet.BitOption(0).SetBit(packet.CapabilityEbit),
	})
	ins.Backbone.AddInterface(&InterfaceConfig{
		IfName:             c.IfName,
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

func (i *Instance) start() {
	i.Backbone.start()
}

func (i *Instance) shutdown() {
	i.Backbone.shutdown()
}
