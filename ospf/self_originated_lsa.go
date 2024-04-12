package ospf

import (
	"github.com/gopacket/gopacket/layers"

	"github.com/povsister/dns-circuit/ospf/packet"
)

func (i *Interface) newRouterLSA() packet.LSAdvertisement {
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
			LinkStateID: i.Area.ins.RouterId,
			AdvRouter:   i.Area.ins.RouterId,
			LSSeqNumber: packet.InitialSequenceNumber,
			LSOptions: func() uint8 {
				ret := packet.BitOption(0)
				if i.Area.ExternalRoutingCapability {
					ret = ret.SetBit(packet.CapabilityEbit)
				}
				return uint8(ret)
			}(),
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
						LinkID: i.DR.Load(),
						//连接数据，其值取决于连接的类型：
						//unnumbered P2P：接口的索引值。
						//Stub网络：子网掩码。
						//其他连接：设备接口的IP地址。
						LinkData: ipv4BytesToUint32(i.Address.IP.To4()),
						Metric:   10,
					},
				},
			},
		},
	}
	return routerLSA
}

func (a *Area) tryUpdatingExistingLSA(id packet.LSAIdentity, i *Interface, modFn func(lsa *packet.LSAdvertisement)) (exist bool) {
	_, lsa, _, ok := a.lsDbGetLSAByIdentity(id, true)
	if ok {
		modFn(&lsa)
		if err := lsa.FixLengthAndChkSum(); err != nil {
			logErr("Area %v err fix LSA chkSum while updating with interface %v: %v\n%v", a.AreaId, i.c.ifi.Name, err, lsa)
			return true
		}
		a.lsDbInstallNewLSA(lsa, false)
		logDebug("Area %v successfully updated LSA with interface %v:\n%v", a.AreaId, i.c.ifi.Name, lsa)
		a.ins.floodLSA(a, i, lsa, a.ins.RouterId)
		return true
	}
	return false
}

func (a *Area) originatingNewLSA(i *Interface, lsa packet.LSAdvertisement) {
	if err := lsa.FixLengthAndChkSum(); err != nil {
		logErr("Area %v err fix LSA chkSum while originating with interface %v: %v\n%v", a.AreaId, i.c.ifi.Name, err, lsa)
		return
	}
	a.lsDbInstallNewLSA(lsa, true)
	logDebug("Area %v successfully originated new LSA with interface %v:\n%v", a.AreaId, i.c.ifi.Name, lsa)
	a.ins.floodLSA(a, i, lsa, a.ins.RouterId)
}

func (a *Area) updateLSDBWhenInterfaceAdd(i *Interface) {
	// need update RouterLSA when interface updated.
	logDebug("Updating self-originated RouterLSA with newly added interface %v", i.c.ifi.Name)
	if !a.tryUpdatingExistingLSA(packet.LSAIdentity{
		LSType:      layers.RouterLSAtypeV2,
		LinkStateId: a.ins.RouterId,
		AdvRouter:   a.ins.RouterId,
	}, i, func(lsa *packet.LSAdvertisement) {
		// update existing LSA
		rtLSA, err := lsa.AsV2RouterLSA()
		if err != nil {
			logErr("Area %v err AsV2RouterLSA with interface %v when new ifi added: %v", a.AreaId, i.c.ifi.Name, err)
			return
		}
		lsa.PrepareReOriginating() // update LSA header for re-originating
		rtLSA.Content.Routers = append(rtLSA.Content.Routers, packet.RouterV2{
			RouterV2: layers.RouterV2{
				Type:     2,
				LinkID:   i.DR.Load(),
				LinkData: ipv4BytesToUint32(i.Address.IP.To4()),
				Metric:   10,
			},
		})
		rtLSA.Content.Links = uint16(len(rtLSA.Content.Routers))
		lsa.Content = rtLSA.Content
	}) {
		// LSA not found. originating a new one.
		a.originatingNewLSA(i, i.newRouterLSA())
	}
}

func (a *Area) updateLSDBWhenDRorBDRChanged(i *Interface) {
	// need update RouterLSA when DR updated.
	logDebug("Updating self-originated RouterLSA with new DR/BDR")
	if !a.tryUpdatingExistingLSA(packet.LSAIdentity{
		LSType:      layers.RouterLSAtypeV2,
		LinkStateId: a.ins.RouterId,
		AdvRouter:   a.ins.RouterId,
	}, i, func(lsa *packet.LSAdvertisement) {
		rtLSA, err := lsa.AsV2RouterLSA()
		if err != nil {
			logErr("Area %v err AsV2RouterLSA with interface %v when DR/BDR change: %v", a.AreaId, i.c.ifi.Name, err)
			return
		}
		lsa.PrepareReOriginating()
		for idx := 0; idx < len(rtLSA.Content.Routers); idx++ {
			rt := rtLSA.Content.Routers[idx]
			rt.LinkID = i.DR.Load()
			rtLSA.Content.Routers[idx] = rt
		}
		lsa.Content = rtLSA.Content
	}) {
		logErr("Area %v err update RouterLSA while DR/BDR changed with interface %v: unexpected no existing routerLSA found",
			a.AreaId, i.c.ifi.Name)
	}
}
