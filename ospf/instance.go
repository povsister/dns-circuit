package ospf

type InstanceConfig struct {
	RouterId uint32
}

type Instance struct {
	cfg  *InstanceConfig
	Area *Area // simply backbone
}

type Area struct {
	Id uint32
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

type SPFTree struct {
}
