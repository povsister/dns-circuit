package main

import (
	"net"
	"syscall"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func main() {
	sock, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		panic(err)
	}
	defer syscall.Close(sock)

	err = syscall.SetsockoptInt(sock, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1)
	if err != nil {
		panic(err)
	}

	ipHeader := &layers.IPv4{
		Version:  4,
		TTL:      1,
		SrcIP:    net.ParseIP("127.0.0.1"),
		Protocol: syscall.IPPROTO_RAW,
		DstIP:    net.ParseIP("127.0.0.1"),
	}

	pBuf := gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(pBuf, gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}, ipHeader, gopacket.Payload("debug"))

	data := pBuf.Bytes()
	// for freeBSD macos ios etc
	//binary.NativeEndian.PutUint16(data[2:], ipHeader.Length)

	dstSockAddr := syscall.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}

	err = syscall.Sendto(sock, data, 0, &dstSockAddr)
	if err != nil {
		panic(err)
	}

}
