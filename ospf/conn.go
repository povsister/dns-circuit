package ospf

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"runtime"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/net/ipv4"

	"github.com/povsister/dns-circuit/iface"
)

const (
	// AllSPFRouters 广播网络上，所有运行 OSPF 的路由器必须准备接收发送到该地址的包. per RFC2328 A.1
	AllSPFRouters = "224.0.0.5"
	// AllDRouters 广播网络上，DR 和 BDR 必须准备接收发送到该地址的包. per RFC2328 A.1
	AllDRouters = "224.0.0.6"

	// IPProtocolNum OSPF申请的IP协议号. per RFC2328 A.1
	IPProtocolNum = 89
	// IPPacketTos OSPF使用的IP包类别和优先级. per RFC2328 A.1 and RFC791 3.1
	IPPacketTos = 0b11000000 // 0xc0

	MulticastTTL = 1
)

type Conn struct {
	Version         int
	multicastGroups []*net.IPAddr
	ifi             *net.Interface
	addr            string
	laddr           net.IP
	rc              *ipv4.RawConn
}

func (o *Conn) Close() error {
	for _, gp := range o.multicastGroups {
		_ = o.rc.LeaveGroup(o.ifi, gp)
	}
	return o.rc.Close()
}

func ListenOSPFv2Multicast(ctx context.Context, ifi *net.Interface, addr string) (ospf *Conn, err error) {
	ospf = &Conn{
		Version: 2,
		addr:    addr,
		laddr:   net.ParseIP(addr),
		ifi:     ifi,
	}
	rc, err := iface.ListenIPv4ByProtocol(ctx, IPProtocolNum, addr,
		func(rc *ipv4.RawConn) error {
			// 绑定多播的接口
			return rc.SetMulticastInterface(ifi)
		}, func(rc *ipv4.RawConn) error {
			// 为了确保多播的包不会传送多跳，IP 包的 TTL 必须设定为 1
			return rc.SetMulticastTTL(MulticastTTL)
		}, func(rc *ipv4.RawConn) error {
			// 所有的 OSPF 路由协议包使用数值为二进制 0000 的普通 TOS 服务,
			// 路由协议包中的 IP 优先级被应该被设定为 Internetwork Control
			return rc.SetTOS(IPPacketTos)
		}, func(rc *ipv4.RawConn) error {
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
					return fmt.Errorf("err at join multicast IP %v at ifi %v: %w", gp, ifi, err)
				}
			}
			ospf.multicastGroups = groups
			return
		})
	if err != nil {
		return
	}
	ospf.rc = rc

	return
}

func (o *Conn) Read(buf []byte) (int, *ipv4.Header, error) {
	_ = o.rc.SetReadDeadline(time.Now().Add(1 * time.Second))
	h, payload, _, err := o.rc.ReadFrom(buf)
	return len(payload) + ipv4.HeaderLen, h, err
}

func (o *Conn) Write(buf []byte) (int, error) {
	dst := net.ParseIP(AllSPFRouters)
	dstIPAddr, _ := net.ResolveIPAddr("ip4", AllSPFRouters)
	ip := &layers.IPv4{
		Version:  ipv4.Version,
		TTL:      MulticastTTL,
		TOS:      IPPacketTos,
		Protocol: IPProtocolNum,
		SrcIP:    o.laddr,
		DstIP:    dst,
	}

	err := o.rc.SetWriteDeadline(time.Now().Add(1 * time.Second))
	if err != nil {
		return 0, err
	}
	pBuf := gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(pBuf, gopacket.SerializeOptions{
		FixLengths: true,
	}, ip, gopacket.Payload(buf))
	if err != nil {
		return 0, err
	}
	switch runtime.GOOS {
	case "darwin", "ios":
		// Before FreeBSD 11.0 packets received on raw IP sockets had the ip_len and ip_off fields converted to host byte order.
		// Packets written to raw IP sockets were expected to have ip_len and ip_off in host byte order.
		binary.NativeEndian.PutUint16(pBuf.Bytes()[2:], ip.Length)
	}

	//dumpBuf(pBuf.Bytes())
	n, err := o.rc.WriteToIP(pBuf.Bytes(), dstIPAddr)
	return n, err
}

func dumpBuf(data []byte) string {
	ret := &strings.Builder{}
	for idx, b := range data {
		if idx > 0 {
			fmt.Fprintf(ret, " ")
		}
		if b <= 0xf {
			fmt.Fprintf(ret, "0%x", b)
		} else {
			fmt.Fprintf(ret, "%x", b)
		}
		if idx >= len(data)-1 {
			fmt.Fprintf(ret, "\n")
		}
	}
	return ret.String()
}
