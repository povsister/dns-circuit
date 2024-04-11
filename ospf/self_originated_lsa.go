package ospf

import (
	"fmt"

	"github.com/gopacket/gopacket/layers"

	"github.com/povsister/dns-circuit/ospf/packet"
)

func (i *Interface) newRouterLSA() (packet.LSAdvertisement, error) {
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
	// marshal can fix length and chksum
	err := routerLSA.FixLengthAndChkSum()
	return routerLSA, err
}

func (a *Area) updateLSDBWhenInterfaceAdd(i *Interface) {
	// need update RouterLSA when interface updated.
	_, lsa, _, ok := a.lsDbGetLSAByIdentity(packet.LSAIdentity{
		LSType:      layers.RouterLSAtypeV2,
		LinkStateId: a.ins.RouterId,
		AdvRouter:   a.ins.RouterId,
	}, true)
	var (
		err error
	)
	defer func() {
		if err != nil {
			logErr("Area %v err update routerLSA when interface %v added: %v", a.AreaId, i.c.ifi.Name, err)
		}
	}()
	if ok {
		var rtLSA packet.LSAdv[packet.V2RouterLSA]
		rtLSA, err = lsa.AsV2RouterLSA()
		if err != nil {
			return
		}
		lsa.LSSeqNumber = uint32(int32(lsa.LSSeqNumber) + 1) // TODO: deal with maxSeqNum
		lsa.LSAge = 0
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
		if err = lsa.FixLengthAndChkSum(); err != nil {
			return
		}
		logDebug("Updated self-originated RouterLSA when interface %v added:\n%+v", i.c.ifi.Name, lsa)
		a.ins.floodLSA(a, i, lsa, a.ins.RouterId)
	} else {
		lsa, err = i.newRouterLSA()
		if err != nil {
			return
		}
		logDebug("Initial self-originated RouterLSA when interface %v added:\n%+v", i.c.ifi.Name, lsa)
		a.lsDbInstallNewLSA(lsa, false)
		a.ins.floodLSA(a, i, lsa, a.ins.RouterId)
	}
}

func (a *Area) updateLSDBWhenDRorBDRChanged(i *Interface) {
	// need update RouterLSA when DR updated.
	_, lsa, _, ok := a.lsDbGetLSAByIdentity(packet.LSAIdentity{
		LSType:      layers.RouterLSAtypeV2,
		LinkStateId: a.ins.RouterId,
		AdvRouter:   a.ins.RouterId,
	}, true)
	var (
		err error
	)
	defer func() {
		if err != nil {
			logErr("Area %v err update routerLSA when DR or BDR changed at interface %v: %v", a.AreaId, i.c.ifi.Name, err)
		}
	}()
	if !ok {
		err = fmt.Errorf("unexpected no existing routerLSA found")
		return
	}
	var rtLSA packet.LSAdv[packet.V2RouterLSA]
	rtLSA, err = lsa.AsV2RouterLSA()
	if err != nil {
		return
	}
	lsa.LSSeqNumber = uint32(int32(lsa.LSSeqNumber) + 1) // TODO: deal with maxSeqNum
	lsa.LSAge = 0
	for idx := 0; idx < len(rtLSA.Content.Routers); idx++ {
		rt := rtLSA.Content.Routers[idx]
		rt.LinkID = i.DR.Load()
		rtLSA.Content.Routers[idx] = rt
	}
	lsa.Content = rtLSA.Content
	if err = lsa.FixLengthAndChkSum(); err != nil {
		return
	}
	logDebug("Updated self-originated RouterLSA when DR/BDR changed:\n%+v", lsa)
	a.lsDbInstallNewLSA(lsa, false)
	a.ins.floodLSA(a, i, lsa, a.ins.RouterId)
}
