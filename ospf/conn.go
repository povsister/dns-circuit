package ospf

import (
	"fmt"
	"github.com/povsister/dns-circuit/iface"
	"golang.org/x/net/ipv4"
	"net"
)

const (
	// AllSPFRouters 广播网络上，所有运行 OSPF 的路由器必须准备接收发送到该地址的包. per RFC2328 A.1
	AllSPFRouters = "224.0.0.5"
	// AllDRouters 广播网络上，DR 和 BDR 必须准备接收发送到该地址的包. per RFC2328 A.1
	AllDRouters = "224.0.0.6"

	// IPProtocolNum OSPF申请的IP协议号. per RFC2328 A.1
	IPProtocolNum = 89
	// IPPacketTos OSPF使用的IP包类别和优先级. per RFC2328 A.1 and RFC791 3.1
	IPPacketTos = 0b11000000
)

type Conn struct {
	Version         int
	multicastGroups []*net.IPAddr
	ifi             *net.Interface
	rc              *ipv4.RawConn
}

func (o *Conn) Close() error {
	for _, gp := range o.multicastGroups {
		_ = o.rc.LeaveGroup(o.ifi, gp)
	}
	return o.rc.Close()
}

func ListenOSPFv2Multicast(ifi *net.Interface) (ospf *Conn, err error) {
	ospf = &Conn{
		Version: 2,
		ifi:     ifi,
	}
	rc, err := iface.ListenIPv4ByProtocol(IPProtocolNum, "",
		func(rc *ipv4.RawConn) error {
			// 绑定多播的接口
			return rc.SetMulticastInterface(ifi)
		}, func(rc *ipv4.RawConn) error {
			// 为了确保多播的包不会传送多跳，IP 包的 TTL 必须设定为 1
			return rc.SetMulticastTTL(1)
		}, func(rc *ipv4.RawConn) error {
			// 所有的 OSPF 路由协议包使用数值为二进制 0000 的普通 TOS 服务,
			// 路由协议包中的 IP 优先级被应该被设定为 Internetwork Control
			return rc.SetTOS(IPPacketTos)
		}, func(rc *ipv4.RawConn) error {
			// 不接收自己发出的多播包
			return rc.SetMulticastLoopback(false)
		}, func(rc *ipv4.RawConn) (err error) {
			// 加入指定的multicast group
			groups := []*net.IPAddr{{IP: net.ParseIP(AllSPFRouters)}}
			// 只要不是PTP接口就绑一下DR
			if ifi.Flags&net.FlagPointToPoint == 0 {
				groups = append(groups, &net.IPAddr{IP: net.ParseIP(AllDRouters)})
			}
			for _, gp := range groups {
				if err = rc.JoinGroup(ifi, gp); err != nil {
					return fmt.Errorf("err at join multicast IP %v: %w", gp, err)
				}
			}
			ospf.multicastGroups = groups
			return
		})
	ospf.rc = rc
	return
}
