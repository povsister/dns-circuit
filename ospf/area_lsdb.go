package ospf

import (
	"fmt"
	"time"

	"github.com/google/gopacket/layers"

	"github.com/povsister/dns-circuit/ospf/packet"
)

func (a *Area) updateLSDBWhenInterfaceAdd(i *Interface) {
	routerLSA := &LSDBRouterItem{
		h: packet.LSAheader{
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
		l: packet.V2RouterLSA{
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
						LinkID: i.DR.Load(),
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
	a.lsDbRw.Lock()
	defer a.lsDbRw.Unlock()
	a.RouterLSAs[routerLSA.h.GetLSAIdentity()] = routerLSA
}

func (a *Area) lsDbInstallLSA(lsa packet.LSAdvertisement) {
	a.lsDbRw.Lock()
	defer a.lsDbRw.Unlock()

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

func (a *Area) getLSReqListFromDD(dd *packet.OSPFv2Packet[packet.DbDescPayload]) (ret []packet.LSReq) {
	for _, l := range dd.Content.LSAinfo {
		if dbLSAh, _, _, exist := a.lsDbGetLSAByIdentity(l.GetLSAIdentity(), false); !exist {
			// LSA not exist
			ret = append(ret, l.GetLSReq())
		} else if l.IsMoreRecentThan(dbLSAh) {
			// neighbors LSA is newer
			ret = append(ret, l.GetLSReq())
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

func (a *Area) tryLSDbUpdateByLSA(l packet.LSAdvertisement) (ack packet.LSAheader, err error) {
	// TODO:
	return
}
