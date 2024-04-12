package ospf

import (
	"fmt"
	"time"

	"github.com/gopacket/gopacket/layers"

	"github.com/povsister/dns-circuit/ospf/packet"
)

func (a *Area) lsDbInstallLSA(lsa packet.LSAdvertisement, meta *lsaMeta) error {
	var err error
	a.lsDbRw.Lock()
	defer a.lsDbRw.Unlock()
	switch lsa.LSType {
	case layers.RouterLSAtypeV2:
		var item packet.LSAdv[packet.V2RouterLSA]
		item, err = lsa.AsV2RouterLSA()
		if err == nil {
			a.RouterLSAs[lsa.GetLSAIdentity()] = &LSDBRouterItem{
				lsaMeta: meta,
				h:       item.LSAheader, l: item.Content,
			}
		}
	case layers.NetworkLSAtypeV2:
		var item packet.LSAdv[packet.V2NetworkLSA]
		item, err = lsa.AsV2NetworkLSA()
		if err == nil {
			a.NetworkLSAs[lsa.GetLSAIdentity()] = &LSDBNetworkItem{
				lsaMeta: meta,
				h:       item.LSAheader, l: item.Content,
			}
		}
	case layers.SummaryLSANetworktypeV2:
		var item packet.LSAdv[packet.V2SummaryLSAType3]
		item, err = lsa.AsV2SummaryLSAType3()
		if err == nil {
			a.SummaryLSAs[lsa.GetLSAIdentity()] = &LSDBSummaryItem{
				lsaMeta: meta,
				h:       item.LSAheader, l: item.Content.V2SummaryLSAImpl,
			}
		}
	case layers.SummaryLSAASBRtypeV2:
		var item packet.LSAdv[packet.V2SummaryLSAType4]
		item, err = lsa.AsV2SummaryLSAType4()
		if err == nil {
			a.SummaryLSAs[lsa.GetLSAIdentity()] = &LSDBSummaryItem{
				lsaMeta: meta,
				h:       item.LSAheader, l: item.Content.V2SummaryLSAImpl,
			}
		}
	case layers.ASExternalLSAtypeV2:
		var item packet.LSAdv[packet.V2ASExternalLSA]
		item, err = lsa.AsV2ASExternalLSA()
		if err == nil {
			a.ins.lsDbSetExtLSA(lsa.GetLSAIdentity(), &LSDBASExternalItem{
				lsaMeta: meta,
				h:       item.LSAheader, l: item.Content,
			})
		}
	}
	return err
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
	// Also, any old instance of the LSA must be removed from the
	//        database when the new LSA is installed.
	// This is done by overwriting with same LSIdentity.
	err := a.lsDbInstallLSA(lsa, newLSAMeta())
	if err != nil {
		logErr("Area %v err install new LSA: %v\n%+v", a.AreaId, err, lsa)
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

func (a *Area) lsDbDeleteLSAByIdentity(id packet.LSAIdentity) {
	a.lsDbRw.Lock()
	defer a.lsDbRw.Unlock()
	switch id.LSType {
	case layers.RouterLSAtypeV2:
		delete(a.RouterLSAs, id)
	case layers.NetworkLSAtypeV2:
		delete(a.NetworkLSAs, id)
	case layers.SummaryLSANetworktypeV2, layers.SummaryLSAASBRtypeV2:
		delete(a.SummaryLSAs, id)
	case layers.ASExternalLSAtypeV2:
		a.ins.lsDbDeleteExtLSA(id)
	}
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

func (lm *lsaMeta) premature() {
	lm.rw.Lock()
	defer lm.rw.Unlock()
	lm.doNotRefresh = true
	lm.ctime.Add(-packet.MaxAge * time.Second)
}

func (lm *lsaMeta) isDoNotRefresh() bool {
	lm.rw.RLock()
	defer lm.rw.RUnlock()
	return lm.doNotRefresh
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
	BelongsArea      *Area
	Id               packet.LSAIdentity
	IsSelfOriginated bool
	DoNotRefresh     bool
}

func (a *Area) agingIntraLSA() (maxAged []agedOutLSA) {
	a.lsDbRw.Lock()
	defer a.lsDbRw.Unlock()

	for id, l := range a.RouterLSAs {
		isSelfOriginated := a.isSelfOriginatedLSA(l.h)
		age := l.doAging()
		if age >= packet.MaxAge || (isSelfOriginated && age >= packet.LSRefreshTime) {
			maxAged = append(maxAged, agedOutLSA{
				a, id, isSelfOriginated, l.isDoNotRefresh(),
			})
		}
	}
	for id, l := range a.NetworkLSAs {
		isSelfOriginated := a.isSelfOriginatedLSA(l.h)
		age := l.doAging()
		if age >= packet.MaxAge || (isSelfOriginated && age >= packet.LSRefreshTime) {
			maxAged = append(maxAged, agedOutLSA{
				a, id, isSelfOriginated, l.isDoNotRefresh(),
			})
		}
	}
	for id, l := range a.SummaryLSAs {
		isSelfOriginated := a.isSelfOriginatedLSA(l.h)
		age := l.doAging()
		if age >= packet.MaxAge || (isSelfOriginated && age >= packet.LSRefreshTime) {
			maxAged = append(maxAged, agedOutLSA{
				a, id, isSelfOriginated, l.isDoNotRefresh(),
			})
		}
	}

	return
}

func (a *Area) lsDbFlushMaxAgedLSA(id packet.LSAIdentity) {
	//   A MaxAge LSA must be removed immediately from the router's link
	//    state database as soon as both a) it is no longer contained on any
	//    neighbor Link state retransmission lists and b) none of the router's
	//    neighbors are in states Exchange or Loading.
	var (
		isInAnyNeighborsReTransmissionList = false
		isAnyNeighobNotFullyAdjed          = false
	)
	for _, i := range a.Interfaces {
		i.rangeOverNeighbors(func(nb *Neighbor) bool {
			nbSt := nb.currState()
			if nbSt == NeighborExchange || nbSt == NeighborLoading {
				isAnyNeighobNotFullyAdjed = true
				return false
			}
			if nb.isInLSRetransmissionList(id) {
				isInAnyNeighborsReTransmissionList = true
				return false
			}
			return true
		})
	}
	if !isInAnyNeighborsReTransmissionList && !isAnyNeighobNotFullyAdjed {
		a.lsDbDeleteLSAByIdentity(id)
		logDebug("Area %v successfully flushed MaxAged LSA: %+v", a.AreaId, id)
	}
}
