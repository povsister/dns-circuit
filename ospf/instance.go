package ospf

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/gopacket/gopacket/layers"

	"github.com/povsister/dns-circuit/ospf/packet"
)

type InstanceConfig struct {
	RouterId           uint32
	HelloInterval      uint16
	RouterDeadInterval uint32
	Network            *net.IPNet
	IfName             string
	ASBR               bool
}

func NewInstance(ctx context.Context, c *InstanceConfig) *Instance {
	ins := &Instance{
		ctx:            ctx,
		RouterId:       c.RouterId,
		ASBR:           c.ASBR,
		ASExternalLSAs: make(map[packet.LSAIdentity]*LSDBASExternalItem),
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
	ctx context.Context

	RouterId uint32
	ASBR     bool
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

	lsDbAgingTicker *TickerFunc
	// Part of the link-state database.  These have originated from the
	//        AS boundary routers.  They comprise routes to destinations
	//        external to the Autonomous System.  Note that, if the router is
	//        itself an AS boundary router, some of these AS-external-LSAs
	//        have been self-originated.
	ASExternalLSAs map[packet.LSAIdentity]*LSDBASExternalItem
	extRw          sync.RWMutex
	// Derived from the link-state database.  Each entry in the routing
	//        table is indexed by a destination, and contains the
	//        destination's cost and a set of paths to use in forwarding
	//        packets to the destination. A path is described by its type and
	//        next hop.  For more information, see Section 11.
	RoutingTable *RoutingTable
}

type LSDBASExternalItem struct {
	*lsaMeta
	h packet.LSAheader
	l packet.V2ASExternalLSA
}

func (l *LSDBASExternalItem) doAging() uint16 {
	l.h.LSAge = l.age()
	return l.h.LSAge
}

func (i *Instance) lsDbGetExtLSA(id packet.LSAIdentity) (*LSDBASExternalItem, bool) {
	i.extRw.RLock()
	defer i.extRw.RUnlock()
	item, ok := i.ASExternalLSAs[id]
	return item, ok
}

func (i *Instance) lsDbSetExtLSA(id packet.LSAIdentity, item *LSDBASExternalItem) {
	i.extRw.Lock()
	defer i.extRw.Unlock()
	i.ASExternalLSAs[id] = item
}

func (i *Instance) lsDbRangeExtLSA(next func(id packet.LSAIdentity, item *LSDBASExternalItem) bool) {
	i.extRw.RLock()
	defer i.extRw.RUnlock()
	for id, item := range i.ASExternalLSAs {
		if !next(id, item) {
			return
		}
	}
}

func (i *Instance) lsDbDeleteExtLSA(id packet.LSAIdentity) {
	i.extRw.Lock()
	defer i.extRw.Unlock()
	delete(i.ASExternalLSAs, id)
}

func (i *Instance) lsDbFlushExtLSA(a *Area) {
	var selfOriginated []packet.LSAIdentity
	defer func() {
		if len(selfOriginated) > 0 {
			logDebug("Area %v flushing %d self-originated external LSAs before shutting down",
				a.AreaId, len(selfOriginated))
		}
		for _, id := range selfOriginated {
			a.prematureLSA(id)
		}
	}()
	i.extRw.RLock()
	defer i.extRw.RUnlock()
	for _, extLSA := range i.ASExternalLSAs {
		if a.isSelfOriginatedLSA(extLSA.h) {
			selfOriginated = append(selfOriginated, extLSA.h.GetLSAIdentity())
		}
	}
}

func (i *Instance) agingExternalLSA() (maxAged []agedOutLSA) {
	i.extRw.Lock()
	defer i.extRw.Unlock()
	for id, l := range i.ASExternalLSAs {
		isSelfOriginated := l.h.AdvRouter == i.RouterId
		age := l.doAging()
		if age >= packet.MaxAge || (isSelfOriginated && age >= packet.LSRefreshTime) {
			maxAged = append(maxAged, agedOutLSA{
				i.Backbone, id, isSelfOriginated, l.isDoNotRefresh(),
			})
		}
	}
	return
}

func (i *Instance) start() {
	lastTotalMaxAged := 0
	i.lsDbAgingTicker = TimeTickerFunc(i.ctx, time.Second, func() {
		lastTotalMaxAged = i.agingLSDB(lastTotalMaxAged)
	})
	i.Backbone.start()
}

// this is needed when some LSA need to premature.
// it prevents LSA from being accidentally refreshed while setting its age to MaxAge.
func (i *Instance) suspendAgingLSDB() {
	i.lsDbAgingTicker.Stop()
}

func (i *Instance) continueAgingLSDB() {
	i.lsDbAgingTicker.Reset()
}

func (i *Instance) agingLSDB(lastTotalMaxAged int) int {
	var totalMaxAged []agedOutLSA
	for _, a := range append(i.Areas, i.Backbone) {
		totalMaxAged = append(totalMaxAged, a.agingIntraLSA()...)
	}
	totalMaxAged = append(totalMaxAged, i.agingExternalLSA()...)
	if lastTotalMaxAged != len(totalMaxAged) {
		if len(totalMaxAged) > 0 {
			logDebug("Aging LSDB done. Total max aged: %v\n%+v", len(totalMaxAged), totalMaxAged)
		} else {
			logDebug("Aging LSDB done. Total max aged: %v", len(totalMaxAged))
		}
	}
	if len(totalMaxAged) > 0 {
		i.flushOrRefreshAgedOutLSAs(totalMaxAged)
	}
	return len(totalMaxAged)
}

func (i *Instance) flushOrRefreshAgedOutLSAs(all []agedOutLSA) {
	for _, l := range all {
		if l.IsSelfOriginated {
			if !l.DoNotRefresh {
				l.BelongsArea.refreshSelfOriginatedLSA(l.Id)
			}
		} else {
			l.BelongsArea.lsDbFlushMaxAgedLSA(l.Id)
		}
	}
}

func (i *Instance) shutdown() {
	for _, a := range append(i.Areas, i.Backbone) {
		i.lsDbFlushExtLSA(a)
		a.shutdown()
	}
}

func (i *Instance) floodLSA(fromArea *Area, fromIfi *Interface, l packet.LSAheader, fromRtId uint32) {
	// Depending upon the LSA's LS type, the LSA can be flooded out
	//        only certain interfaces.  These interfaces, defined by the
	//        following, are called the eligible interfaces:

	var eligibleInterfaces []*Interface
	switch l.LSType {
	case layers.ASExternalLSAtypeV2:
		// AS-external-LSAs are flooded throughout the entire AS, with
		//            the exception of stub areas (see Section 3.6).  The eligible
		//            interfaces are all the router's interfaces, excluding
		//            virtual links and those interfaces attaching to stub areas.
		for _, a := range append(i.Areas, i.Backbone) {
			if !a.ExternalRoutingCapability {
				continue
			}
			for _, ifi := range a.Interfaces {
				if ifi.Type == IfTypeVirtualLink {
					continue
				}
				eligibleInterfaces = append(eligibleInterfaces, ifi)
			}
		}
	default:
		// All other types are specific to a single area (Area A).  The
		//            eligible interfaces are all those interfaces attaching to
		//            the Area A.  If Area A is the backbone, this includes all
		//            the virtual links.
		for _, ifi := range fromArea.Interfaces {
			if ifi.Type != IfTypeVirtualLink || fromArea.AreaId == 0 {
				eligibleInterfaces = append(eligibleInterfaces, ifi)
			}
		}
	}

	// Link state databases must remain synchronized over all
	//        adjacencies associated with the above eligible interfaces.  This
	//        is accomplished by executing the following steps on each
	//        eligible interface.  It should be noted that this procedure may
	//        decide not to flood an LSA out a particular interface, if there
	//        is a high probability that the attached neighbors have already
	//        received the LSA.  However, in these cases the flooding
	//        procedure must be absolutely sure that the neighbors eventually
	//        do receive the LSA, so the LSA is still added to each
	//        adjacency's Link state retransmission list.  For each eligible
	//        interface:
	for _, ifi := range eligibleInterfaces {
		ifiSt := ifi.currState()
		addedToNebosReTransmissionList := false
		ifi.rangeOverNeighbors(func(nb *Neighbor) bool {
			// Each of the neighbors attached to this interface are
			//            examined, to determine whether they must receive the new
			//            LSA.  The following steps are executed for each neighbor:
			nbSt := nb.currState()
			// If the neighbor is in a lesser state than Exchange, it
			//                does not participate in flooding, and the next neighbor
			//                should be examined.
			if nbSt < NeighborExchange {
				return true
			}
			// Else, if the adjacency is not yet full (neighbor state
			//                is Exchange or Loading), examine the Link state request
			//                list associated with this adjacency.  If there is an
			//                instance of the new LSA on the list, it indicates that
			//                the neighboring router has an instance of the LSA
			//                already.  Compare the new LSA to the neighbor's copy:
			if nbSt == NeighborExchange || nbSt == NeighborLoading {
				if lsr, ok := nb.getFromLSReqList(l.GetLSAIdentity()); ok {
					if lsr.IsMoreRecentThan(l) {
						logDebug("LSA in LSReqList in newer, still need this req")
						//If the new LSA is less recent, then examine the next neighbor.
						return true
					} else if l.IsSame(lsr) {
						logDebug("LSA in LSReqList is same, this is what we requested. Delete req from list.")
						// If the two copies are the same instance, then delete
						//                    the LSA from the Link state request list, and
						//                    examine the next neighbor.
						nb.deleteFromLSReqList(l.GetLSAIdentity())
						return true
					} else {
						logDebug("LSA in LSReqList is older. Delete req from list.")
						// Else, the new LSA is more recent.  Delete the LSA
						//                    from the Link state request list.
						nb.deleteFromLSReqList(l.GetLSAIdentity())
					}
				}
			}
			// If the new LSA was received from this neighbor, examine the next neighbor.
			if fromRtId == nb.NeighborId {
				return true
			}
			// At this point we are not positive that the neighbor has
			//                an up-to-date instance of this new LSA.  Add the new LSA
			//                to the Link state retransmission list for the adjacency.
			//                This ensures that the flooding procedure is reliable;
			//                the LSA will be retransmitted at intervals until an
			//                acknowledgment is seen from the neighbor.
			// Note that this will not immediately send out a LSU.
			// It's only for re-transmission purpose.
			nb.addToLSRetransmissionList(l.GetLSAIdentity())
			addedToNebosReTransmissionList = true
			return true
		})

		// The router must now decide whether to flood the new LSA out
		//            this interface.  If in the previous step, the LSA was NOT
		//            added to any of the Link state retransmission lists, there
		//            is no need to flood the LSA out the interface and the next
		//            interface should be examined.
		if !addedToNebosReTransmissionList {
			continue
		}

		// If the new LSA was received on this interface, and it was
		//            received from either the Designated Router or the Backup
		//            Designated Router, chances are that all the neighbors have
		//            received the LSA already.  Therefore, examine the next
		//            interface.
		if fromIfi == ifi && fromRtId == ifi.DR.Load() || fromRtId == ifi.BDR.Load() {
			continue
		}

		// If the new LSA was received on this interface, and the
		//            interface state is Backup (i.e., the router itself is the
		//            Backup Designated Router), examine the next interface.  The
		//            Designated Router will do the flooding on this interface.
		//            However, if the Designated Router fails the router (i.e.,
		//            the Backup Designated Router) will end up retransmitting the
		//            updates.
		if fromIfi == ifi && ifiSt == InterfaceBackup {
			continue
		}

		// If this step is reached, the LSA must be flooded out the
		//            interface.  Send a Link State Update packet (including the
		//            new LSA as contents) out the interface.  The LSA's LS age
		//            must be incremented by InfTransDelay (which must be > 0)
		//            when it is copied into the outgoing Link State Update packet
		//            (until the LS age field reaches the maximum value of
		//            MaxAge).
		switch ifi.Type {
		// On broadcast networks, the Link State Update packets are
		//            multicast.  The destination IP address specified for the
		//            Link State Update Packet depends on the state of the
		//            interface.  If the interface state is DR or Backup, the
		//            address AllSPFRouters should be used.  Otherwise, the
		//            address AllDRouters should be used.
		case IfTypeBroadcast:
			var dst uint32 = allDRouters
			if ifiSt == InterfaceDR || ifiSt == InterfaceBackup {
				dst = allSPFRouters
			}
			ifi.sendLSUFlood(l.GetLSAIdentity(), dst)
		default:
			// On non-broadcast networks, separate Link State Update
			//            packets must be sent, as unicasts, to each adjacent neighbor
			//            (i.e., those in state Exchange or greater).  The destination
			//            IP addresses for these packets are the neighbors' IP
			//            addresses.
			ifi.immediateTickNeighborsRetransmissionList()
		}
	}
}

func (i *Instance) addTestASBRLSA() {
	l := packet.LSAdvertisement{
		LSAheader: packet.LSAheader{
			LSType:      layers.ASExternalLSAtypeV2,
			LinkStateID: ipv4BytesToUint32(net.IPv4(142, 251, 220, 0).To4()), // google
			AdvRouter:   i.RouterId,
			LSSeqNumber: packet.InitialSequenceNumber,
			LSOptions:   uint8(packet.BitOption(0).SetBit(packet.CapabilityEbit)),
		},
		Content: packet.V2ASExternalLSA{
			NetworkMask: ipv4MaskToUint32(net.IPv4Mask(255, 255, 255, 0)),
			ExternalBit: uint8(packet.BitOption(0).SetBit(packet.ASExternalLSAFlagEbit)),
			Metric:      10000,
		},
	}
	if !i.Backbone.tryUpdatingExistingLSA(l.GetLSAIdentity(), nil, func(lsa *packet.LSAdvertisement) {
		lsa.Content = l.Content
	}) {
		i.Backbone.originatingNewLSA(l)
	}
}

func (i *Instance) recalculateRoutes() {
	// TODO: recalculate route
}
