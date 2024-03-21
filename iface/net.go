package iface

import (
	"fmt"
	"net"

	"golang.org/x/net/ipv4"
)

func ListenIPv4ByProtocol(protoNum int, addr string, modRc ...func(rc *ipv4.RawConn) error) (rc *ipv4.RawConn, err error) {
	nl, err := net.ListenPacket(fmt.Sprintf("ip4:%d", protoNum), addr)
	if err != nil {
		return
	}
	rc, err = ipv4.NewRawConn(nl)
	// enable all ctrl msg
	if err = rc.SetControlMessage(^ipv4.ControlFlags(0), true); err != nil {
		return
	}
	for idx, modFn := range modRc {
		if err = modFn(rc); err != nil {
			return nil, fmt.Errorf("err at modRc idx(%d): %w", idx, err)
		}
	}
	return
}
