package ospf

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/povsister/dns-circuit/ospf/packet"
)

type AreaConfig struct {
	Instance *Instance
	AreaId   uint32
	Address  *AreaAddress
	Options  packet.BitOption
}

func NewArea(ctx context.Context, c *AreaConfig) *Area {
	return &Area{
		ctx:                       ctx,
		ins:                       c.Instance,
		AreaId:                    c.AreaId,
		Addresses:                 []*AreaAddress{c.Address},
		RouterLSAs:                make(map[packet.LSAIdentity]*LSDBRouterItem),
		NetworkLSAs:               make(map[packet.LSAIdentity]*LSDBNetworkItem),
		SummaryLSAs:               make(map[packet.LSAIdentity]*LSDBSummaryItem),
		Options:                   c.Options,
		ExternalRoutingCapability: c.Options.IsBitSet(packet.CapabilityEbit),
		TransitCapability:         true,
	}
}

func (a *Area) AddInterface(c *InterfaceConfig) {
	i := NewInterface(a.ctx, c)
	i.Area = a
	a.Interfaces = append(a.Interfaces, i)
	a.updateLSDBWhenInterfaceAdd(i)
}

type Area struct {
	ctx context.Context
	wg  sync.WaitGroup

	ins     *Instance
	Options packet.BitOption

	// A 32-bit number identifying the area. The Area ID of 0.0.0.0 is
	//        reserved for the backbone.
	AreaId uint32
	// List of area address ranges
	// In order to aggregate routing information at area boundaries,
	// area address ranges can be employed. Each address range is
	// specified by an [address,mask] pair and a status indication of
	// either Advertise or DoNotAdvertise
	Addresses []*AreaAddress
	// This router's interfaces connecting to the area.  A router
	// interface belongs to one and only one area (or the backbone).
	// For the backbone area this list includes all the virtual links.
	// A virtual link is identified by the Router ID of its other
	// endpoint; its cost is the cost of the shortest intra-area path
	// through the Transit area that exists between the two routers.
	Interfaces []*Interface

	// A router has a separate link state database for every area to
	// which it belongs. All routers belonging to the same area have
	// identical link state databases for the area.
	// Link-state database is composed of router-LSAs, network-LSAs and
	// summary-LSAs (all listed in the area data structure).  In
	// addition, external routes (AS-external-LSAs) are included in all
	// non-stub area databases (see Section 3.6).

	lsDbRw sync.RWMutex
	// A router-LSA is generated by each router in the area.  It
	// describes the state of the router's interfaces to the area.
	RouterLSAs map[packet.LSAIdentity]*LSDBRouterItem

	// One network-LSA is generated for each transit broadcast and NBMA
	// network in the area.  A network-LSA describes the set of routers
	// currently connected to the network.
	NetworkLSAs map[packet.LSAIdentity]*LSDBNetworkItem

	// Summary-LSAs originate from the area's area border routers.
	// They describe routes to destinations internal to the Autonomous
	// System, yet external to the area (i.e., inter-area
	// destinations).
	SummaryLSAs map[packet.LSAIdentity]*LSDBSummaryItem

	// This parameter indicates whether the area can carry data traffic
	// that neither originates nor terminates in the area itself. This
	// parameter is calculated when the area's shortest-path tree is
	// built (see Section 16.1, where TransitCapability is set to TRUE
	// if and only if there are one or more fully adjacent virtual
	// links using the area as Transit area), and is used as an input
	// to a subsequent step of the routing table build process (see
	// Section 16.3). When an area's TransitCapability is set to TRUE,
	// the area is said to be a "transit area".
	TransitCapability bool

	// Whether AS-external-LSAs will be flooded into/throughout the
	// area.  This is a configurable parameter.  If AS-external-LSAs
	// are excluded from the area, the area is called a "stub". Within
	// stub areas, routing to AS external destinations will be based
	// solely on a default summary route.  The backbone cannot be
	// configured as a stub area.  Also, virtual links cannot be
	// configured through stub areas.  For more information, see
	// Section 3.6.
	ExternalRoutingCapability bool

	// If the area has been configured as a stub area, and the router
	// itself is an area border router, then the StubDefaultCost
	// indicates the cost of the default summary-LSA that the router
	// should advertise into the area. See Section 12.4.3 for more
	// information.
	StubDefaultCost int

	// The shortest-path tree for the area, with this router itself as
	// root.  Derived from the collected router-LSAs and network-LSAs
	// by the Dijkstra algorithm (see Section 16.1).
	SPF *SPFTree
}

type LSDBRouterItem struct {
	*lsaMeta
	h packet.LSAheader
	l packet.V2RouterLSA
}

func (l *LSDBRouterItem) aging() uint16 {
	l.h.LSAge = l.age()
	return l.h.LSAge
}

type LSDBNetworkItem struct {
	*lsaMeta
	h packet.LSAheader
	l packet.V2NetworkLSA
}

func (l *LSDBNetworkItem) aging() uint16 {
	l.h.LSAge = l.age()
	return l.h.LSAge
}

type LSDBSummaryItem struct {
	*lsaMeta
	h packet.LSAheader
	l packet.V2SummaryLSAImpl
}

func (l *LSDBSummaryItem) aging() uint16 {
	l.h.LSAge = l.age()
	return l.h.LSAge
}

type lsaMeta struct {
	rw            sync.RWMutex
	ctime         time.Time
	lastFloodTime time.Time
}

func (lm *lsaMeta) age() uint16 {
	age := time.Since(lm.ctime)
	if age >= 0 && age <= time.Second*packet.MaxAge {
		return uint16(age)
	}
	return packet.MaxAge
}

func (a *Area) start() {
	for _, ifi := range a.Interfaces {
		ifi.start()
	}
}

func (a *Area) shutdown() {
	for _, ifi := range a.Interfaces {
		if err := ifi.close(); err != nil {
			logWarn("Interface %s close err: %v", ifi.c.ifi.Name, err)
		}
	}
	a.wg.Wait()
}

type AreaAddress struct {
	Address *net.IPNet
	// Routing information is condensed at area boundaries.
	// External to the area, at most a single route is
	// advertised (via a summary-LSA) for each address
	// range. The route is advertised if and only if the
	// address range's Status is set to Advertise.
	// Unadvertised ranges allow the existence of certain
	// networks to be intentionally hidden from other
	// areas. Status is set to Advertise by default.
	DoNotAdvertise bool
}

type SPFTree struct {
}
