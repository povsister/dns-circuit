package ospf

import (
	"fmt"
	"time"

	"github.com/gopacket/gopacket/layers"

	"github.com/povsister/dns-circuit/ospf/packet"
)

func (a *Area) updateLSDBWhenInterfaceAdd(i *Interface) {
	routerLSA := packet.LSAdvertisement{
		LSAheader: packet.LSAheader{
			LSType: layers.RouterLSAtypeV2,
			// LS Type   Link State ID
			// _______________________________________________
			// 1         The originating router's Router ID.
			// 2         The IP interface address of the network's Designated Router.
			// 3         The destination network's IP address.
			// 4         The Router ID of the described AS boundary router.
			// 5         The destination network's IP address.
			LinkStateID: a.ins.RouterId,
			AdvRouter:   a.ins.RouterId,
			LSSeqNumber: packet.InitialSequenceNumber,
			LSOptions:   uint8(packet.BitOption(0).SetBit(packet.CapabilityEbit)),
		},
		Content: packet.V2RouterLSA{
			RouterLSAV2: layers.RouterLSAV2{
				Flags: 0,
				Links: 1,
			},
			Routers: []packet.RouterV2{
				{
					RouterV2: layers.RouterV2{
						// Type   Description
						// __________________________________________________
						// 1      Point-to-point connection to another router
						// 2      Connection to a transit network
						// 3      Connection to a stub network
						// 4      Virtual link
						Type: 2,
						// Type   Link ID
						// ______________________________________
						// 1      Neighboring router's Router ID
						// 2      IP address of Designated Router
						// 3      IP network/subnet number
						// 4      Neighboring router's Router ID
						LinkID: i.DR.Load(), // TODO: fix DR change event
						//连接数据，其值取决于连接的类型：
						//unnumbered P2P：接口的索引值。
						//Stub网络：子网掩码。
						//其他连接：设备接口的IP地址。
						LinkData: ipv4BytesToUint32(i.Address.IP.To4()),
						Metric:   20,
					},
				},
			},
		},
	}
	// marshal can fix length and chksum
	err := routerLSA.FixLengthAndChkSum()
	if err != nil {
		logErr("Area %v err add routerLSA when interface %v added: %v", a.AreaId, i.c.ifi, err)
	} else {
		logDebug("Initial self-originated RouterLSA:\n%+v", routerLSA)
		a.lsDbInstallNewLSA(routerLSA, false)
	}
}

func (a *Area) lsDbInstallNewLSA(lsa packet.LSAdvertisement, isNeighborLSRxmChecked bool) {
	// Installing a new LSA in the database, either as the result of
	//        flooding or a newly self-originated LSA, may cause the OSPF
	//        routing table structure to be recalculated.  The contents of the
	//        new LSA should be compared to the old instance, if present.  If
	//        there is no difference, there is no need to recalculate the
	//        routing table. When comparing an LSA to its previous instance,
	//        the following are all considered to be differences in contents:
	h, _, _, exist := a.lsDbGetLSAByIdentity(lsa.GetLSAIdentity(), false)
	// o   The LSA's Options field has changed.
	// o   One of the LSA instances has LS age set to MaxAge, and he other does not.
	// o   The length field in the LSA header has changed.
	// o   The body of the LSA (i.e., anything outside the 20-byte LSA header) has changed.
	//		Note that this excludes changes in LS Sequence Number and LS Checksum.
	if !exist || h.LSOptions != lsa.LSOptions ||
		(h.LSAge == packet.MaxAge && lsa.LSAge != packet.MaxAge) ||
		(h.LSAge != packet.MaxAge && lsa.LSAge == packet.MaxAge) ||
		h.Length != lsa.Length {
		// TODO: compare LSA content
		// If the contents are different, the following pieces of the
		//        routing table must be recalculated, depending on the new LSA's
		//        LS type field:
		// TODO: recalculate route
	}
	// install new LSA into DB
	var err error
	// Also, any old instance of the LSA must be removed from the
	//        database when the new LSA is installed.
	// This is done by overwriting with same LSIdentity.
	a.lsDbRw.Lock()
	defer a.lsDbRw.Unlock()
	switch lsa.LSType {
	case layers.RouterLSAtypeV2:
		var item packet.LSAdv[packet.V2RouterLSA]
		item, err = lsa.AsV2RouterLSA()
		if err == nil {
			a.RouterLSAs[lsa.GetLSAIdentity()] = &LSDBRouterItem{
				lsaMeta: newLSAMeta(),
				h:       item.LSAheader, l: item.Content,
			}
		}
	case layers.NetworkLSAtypeV2:
		var item packet.LSAdv[packet.V2NetworkLSA]
		item, err = lsa.AsV2NetworkLSA()
		if err == nil {
			a.NetworkLSAs[lsa.GetLSAIdentity()] = &LSDBNetworkItem{
				lsaMeta: newLSAMeta(),
				h:       item.LSAheader, l: item.Content,
			}
		}
	case layers.SummaryLSANetworktypeV2:
		var item packet.LSAdv[packet.V2SummaryLSAType3]
		item, err = lsa.AsV2SummaryLSAType3()
		if err == nil {
			a.SummaryLSAs[lsa.GetLSAIdentity()] = &LSDBSummaryItem{
				lsaMeta: newLSAMeta(),
				h:       item.LSAheader, l: item.Content.V2SummaryLSAImpl,
			}
		}
	case layers.SummaryLSAASBRtypeV2:
		var item packet.LSAdv[packet.V2SummaryLSAType4]
		item, err = lsa.AsV2SummaryLSAType4()
		if err == nil {
			a.SummaryLSAs[lsa.GetLSAIdentity()] = &LSDBSummaryItem{
				lsaMeta: newLSAMeta(),
				h:       item.LSAheader, l: item.Content.V2SummaryLSAImpl,
			}
		}
	case layers.ASExternalLSAtypeV2:
		var item packet.LSAdv[packet.V2ASExternalLSA]
		item, err = lsa.AsV2ASExternalLSA()
		if err == nil {
			a.ins.lsDbSetExtLSA(lsa.GetLSAIdentity(), &LSDBASExternalItem{
				lsaMeta: newLSAMeta(),
				h:       item.LSAheader, l: item.Content,
			})
		}
	}
	if err != nil {
		logErr("Area %v err install LSA: %v\n%+v", a.AreaId, err, lsa)
	} else if !isNeighborLSRxmChecked {
		// This old instance must also be removed from all neighbors' Link state retransmission lists (see Section 10).
		a.removeAllNeighborsLSRetransmission(h.GetLSAIdentity())
	}
}

func newLSAMeta() *lsaMeta {
	return &lsaMeta{
		ctime: time.Now(),
	}
}

func (a *Area) lsDbGetDatabaseSummary() (ret []packet.LSAIdentity) {
	a.lsDbRw.RLock()
	defer a.lsDbRw.RUnlock()
	for _, l := range a.RouterLSAs {
		ret = append(ret, l.h.GetLSAIdentity())
	}
	return
}

func (a *Area) lsDbGetLSAheaderByIdentity(ids ...packet.LSAIdentity) (ret []packet.LSAheader) {
	for _, id := range ids {
		if lsaH, _, _, ok := a.lsDbGetLSAByIdentity(id, false); ok {
			ret = append(ret, lsaH)
		}
	}
	return
}

func (a *Area) lsDbGetLSAByIdentity(id packet.LSAIdentity, entireLSA bool) (lsaHdr packet.LSAheader,
	fullLSA packet.LSAdvertisement, meta *lsaMeta, exist bool) {
	a.lsDbRw.RLock()
	defer a.lsDbRw.RUnlock()

	switch id.LSType {
	case layers.RouterLSAtypeV2:
		if rtLSA, ok := a.RouterLSAs[id]; ok {
			lsaHdr, meta, exist = rtLSA.h, rtLSA.lsaMeta, true
			if entireLSA {
				fullLSA.LSAheader, fullLSA.Content = rtLSA.h, rtLSA.l
			}
		}
	case layers.NetworkLSAtypeV2:
		if ntLSA, ok := a.NetworkLSAs[id]; ok {
			lsaHdr, meta, exist = ntLSA.h, ntLSA.lsaMeta, true
			if entireLSA {
				fullLSA.LSAheader, fullLSA.Content = ntLSA.h, ntLSA.l
			}
		}
	case layers.SummaryLSANetworktypeV2, layers.SummaryLSAASBRtypeV2:
		if smLSA, ok := a.SummaryLSAs[id]; ok {
			lsaHdr, meta, exist = smLSA.h, smLSA.lsaMeta, true
			if entireLSA {
				fullLSA.LSAheader, fullLSA.Content = smLSA.h, smLSA.l
			}
		}
	case layers.ASExternalLSAtypeV2:
		if extLSA, ok := a.ins.lsDbGetExtLSA(id); ok {
			lsaHdr, meta, exist = extLSA.h, extLSA.lsaMeta, true
			if entireLSA {
				fullLSA.LSAheader, fullLSA.Content = extLSA.h, extLSA.l
			}
		}
	}
	return
}

func (lm *lsaMeta) isReceivedLessThanMinLSArrival() bool {
	lm.rw.RLock()
	defer lm.rw.RUnlock()
	return time.Since(lm.ctime) <= packet.MinLSArrival*time.Second
}

func (lm *lsaMeta) isLastFloodTimeLongerThanMinLSArrival() bool {
	lm.rw.RLock()
	defer lm.rw.RUnlock()
	return time.Since(lm.lastFloodTime) > packet.MinLSArrival*time.Second
}

func (lm *lsaMeta) updateLastFloodTime() {
	lm.rw.Lock()
	defer lm.rw.Unlock()
	lm.lastFloodTime = time.Now()
}

func (a *Area) getLSReqListFromDD(dd *packet.OSPFv2Packet[packet.DbDescPayload]) (ret []packet.LSAheader) {
	for _, l := range dd.Content.LSAinfo {
		if dbLSAh, _, _, exist := a.lsDbGetLSAByIdentity(l.GetLSAIdentity(), false); !exist {
			// LSA not exist
			ret = append(ret, l)
		} else if l.IsMoreRecentThan(dbLSAh) {
			// neighbors LSA is newer
			ret = append(ret, l)
		}
	}
	return
}

func (a *Area) respondLSReqWithLSU(n *Neighbor, reqs []packet.LSReq) (err error) {
	// Each LSA specified in the Link State Request packet should be
	//        located in the router's database, and copied into Link State
	//        Update packets for transmission to the neighbor.  These LSAs
	//        should NOT be placed on the Link state retransmission list for
	//        the neighbor.
	lsas := make([]packet.LSAdvertisement, 0, len(reqs))
	for _, r := range reqs {
		if _, dt, _, exist := a.lsDbGetLSAByIdentity(r.GetLSAIdentity(), true); exist {
			lsas = append(lsas, dt)
		} else {
			return fmt.Errorf("requested LS(%+v) not exists in LSDB", r)
		}
	}
	if len(lsas) <= 0 {
		return nil
	}
	pkt := sendPkt{
		dst: ipv4BytesToUint32(n.NeighborAddress.To4()),
		p: &packet.OSPFv2Packet[packet.LSUpdatePayload]{
			OSPFv2: a.ospfPktHeader(func(p *packet.LayerOSPFv2) {
				p.Type = layers.OSPFLinkStateUpdate
			}),
			Content: packet.LSUpdatePayload{
				LSUpdate: layers.LSUpdate{
					NumOfLSAs: uint32(len(lsas)),
				},
				LSAs: lsas,
			},
		},
	}
	n.i.queuePktForSend(pkt)
	return
}

func (a *Area) hasNeighborStateIN(sts ...NeighborState) (ret bool) {
	if len(sts) <= 0 {
		return false
	}
	stLUT := make(map[NeighborState]bool, len(sts))
	for _, st := range sts {
		stLUT[st] = true
	}
	for _, ifi := range a.Interfaces {
		ifi.rangeOverNeighbors(func(nb *Neighbor) bool {
			if stLUT[nb.currState()] {
				ret = true
				return false
			}
			return true
		})
	}
	return
}

func (a *Area) removeAllNeighborsLSRetransmission(lsa packet.LSAIdentity) {
	for _, ifi := range a.Interfaces {
		ifi.rangeOverNeighbors(func(nb *Neighbor) bool {
			nb.removeFromLSRetransmissionList(lsa)
			return true
		})
	}
}

func (a *Area) isSelfOriginatedLSA(l packet.LSAheader) bool {
	if l.AdvRouter == a.ins.RouterId {
		return true
	}
	if l.LSType == layers.NetworkLSAtypeV2 {
		for _, ifi := range a.Interfaces {
			if l.LinkStateID == ipv4BytesToUint32(ifi.Address.IP.To4()) {
				return true
			}
		}
	}
	return false
}

type agedOutLSA struct {
	Id               packet.LSAIdentity
	IsSelfOriginated bool
}

func (a *Area) agingLSA() (maxAged []agedOutLSA) {
	a.lsDbRw.Lock()
	defer a.lsDbRw.Unlock()

	for id, l := range a.RouterLSAs {
		if l.aging() >= packet.MaxAge {
			maxAged = append(maxAged, agedOutLSA{
				id, a.isSelfOriginatedLSA(l.h),
			})
		}
	}
	for id, l := range a.NetworkLSAs {
		if l.aging() >= packet.MaxAge {
			maxAged = append(maxAged, agedOutLSA{
				id, a.isSelfOriginatedLSA(l.h),
			})
		}
	}
	for id, l := range a.SummaryLSAs {
		if l.aging() >= packet.MaxAge {
			maxAged = append(maxAged, agedOutLSA{
				id, a.isSelfOriginatedLSA(l.h),
			})
		}
	}

	return
}
