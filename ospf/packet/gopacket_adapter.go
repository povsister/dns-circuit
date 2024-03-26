package packet

import (
	"fmt"
	"unsafe"

	"github.com/google/gopacket/layers"
)

type LayerOSPFv2 layers.OSPFv2

func (l *LayerOSPFv2) AsHello() (*OSPFv2Packet[HelloPayloadV2], error) {
	if hello, ok := l.Content.(layers.HelloPkgV2); ok {
		return &OSPFv2Packet[HelloPayloadV2]{
			OSPFv2:  layers.OSPFv2(*l),
			Content: HelloPayloadV2(hello),
		}, nil
	}
	return nil, fmt.Errorf("expecting layers.HelloPkgV2 but got %T", l.Content)
}

func (l *LayerOSPFv2) AsDbDescription() (*OSPFv2Packet[DbDescPayload], error) {
	if dbDesc, ok := l.Content.(layers.DbDescPkg); ok {
		return &OSPFv2Packet[DbDescPayload]{
			OSPFv2:  layers.OSPFv2(*l),
			Content: DbDescPayload(dbDesc),
		}, nil
	}
	return nil, fmt.Errorf("expecting layers.DbDescPkg but got %T", l.Content)
}

func (l *LayerOSPFv2) AsLSRequest() (*OSPFv2Packet[LSRequestPayload], error) {
	if lsrs, ok := l.Content.([]layers.LSReq); ok {
		return &OSPFv2Packet[LSRequestPayload]{
			OSPFv2:  layers.OSPFv2(*l),
			Content: *(*LSRequestPayload)(unsafe.Pointer(&lsrs)),
		}, nil
	}
	return nil, fmt.Errorf("expecting []layers.LSReq but got %T", l.Content)
}

func (l *LayerOSPFv2) AsLSUpdate() (*OSPFv2Packet[LSUpdatePayload], error) {
	if lsu, ok := l.Content.(layers.LSUpdate); ok {
		ret := &OSPFv2Packet[LSUpdatePayload]{
			OSPFv2:  layers.OSPFv2(*l),
			Content: LSUpdatePayload{LSUpdate: lsu},
		}
		return ret, ret.Content.parse()
	}
	return nil, fmt.Errorf("expecting layers.LSUpdate but got %T", l.Content)
}

func (l *LayerOSPFv2) AsLSAcknowledgment() (*OSPFv2Packet[LSAcknowledgementPayload], error) {
	if lsahs, ok := l.Content.([]layers.LSAheader); ok {
		return &OSPFv2Packet[LSAcknowledgementPayload]{
			OSPFv2:  layers.OSPFv2(*l),
			Content: *(*LSAcknowledgementPayload)(unsafe.Pointer(&lsahs)),
		}, nil
	}
	return nil, fmt.Errorf("expecting []layers.LSAheader but got %T", l.Content)
}
