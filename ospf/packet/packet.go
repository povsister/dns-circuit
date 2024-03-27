package packet

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// OSPFv2Packet wrapper implements SerializeTo.
// Make it possible to serialize an OSPF message to wire format
type OSPFv2Packet[T OSPFPayloadV2] struct {
	layers.OSPFv2
	Content T //replace Content interface for marshaling
}

type OSPFPayloadV2 interface {
	HelloPayloadV2 | DbDescPayload |
		LSRequestPayload | LSUpdatePayload | LSAcknowledgementPayload
	marshalable
}

var (
	ErrBufferLengthTooShort = errors.New("err buffer length too short")
)

type HelloPayloadV2 layers.HelloPkgV2

func (p HelloPayloadV2) Size() int {
	return 20 + 4*len(p.NeighborID)
}

func (p HelloPayloadV2) SerializeToSizedBuffer(b []byte) error {
	if len(b) < p.Size() {
		return ErrBufferLengthTooShort
	}
	binary.BigEndian.PutUint32(b[0:4], p.NetworkMask)
	binary.BigEndian.PutUint16(b[4:6], p.HelloInterval)
	b[6] = uint8(p.Options)
	b[7] = p.RtrPriority
	binary.BigEndian.PutUint32(b[8:12], p.RouterDeadInterval)
	binary.BigEndian.PutUint32(b[12:16], p.DesignatedRouterID)
	binary.BigEndian.PutUint32(b[16:20], p.BackupDesignatedRouterID)
	for idx, neighbor := range p.NeighborID {
		binary.BigEndian.PutUint32(b[20+idx*4:20+(idx+1)*4], neighbor)
	}
	return nil
}

type HelloPayloadV3 layers.HelloPkg

type DbDescPayload struct {
	layers.DbDescPkg
	LSAinfo []LSAheader
}

func (p DbDescPayload) Size() int {
	return 8 + LSAheader{}.Size()*len(p.LSAinfo)
}

func (p DbDescPayload) SerializeToSizedBuffer(b []byte) (err error) {
	if len(b) < p.Size() {
		return ErrBufferLengthTooShort
	}
	binary.BigEndian.PutUint16(b[0:2], p.InterfaceMTU)
	b[2] = uint8(p.Options)
	b[3] = uint8(p.Flags)
	binary.BigEndian.PutUint32(b[4:8], p.DDSeqNumber)
	for idx, lsaH := range p.LSAinfo {
		if err = lsaH.SerializeToSizedBuffer(b[8+idx*lsaH.Size() : 8+(idx+1)*lsaH.Size()]); err != nil {
			return
		}
	}
	return
}

type LSRequestPayload []LSReq

func (p LSRequestPayload) Size() int {
	total := 0
	for _, eachP := range p {
		total += eachP.Size()
	}
	return total
}

func (p LSRequestPayload) SerializeToSizedBuffer(b []byte) (err error) {
	if len(b) < p.Size() {
		return ErrBufferLengthTooShort
	}
	offset := 0
	for _, eachP := range p {
		if err = eachP.SerializeToSizedBuffer(b[offset : offset+eachP.Size()]); err != nil {
			return
		}
		offset += eachP.Size()
	}
	return
}

// LSReq stands for a single link state request entry.
type LSReq layers.LSReq

func (p LSReq) Size() int {
	return 12
}

func (p LSReq) SerializeToSizedBuffer(b []byte) (err error) {
	if len(b) < p.Size() {
		return ErrBufferLengthTooShort
	}
	binary.BigEndian.PutUint32(b[0:4], uint32(p.LSType))
	binary.BigEndian.PutUint32(b[4:8], p.LSID)
	binary.BigEndian.PutUint32(b[8:12], p.AdvRouter)
	return
}

type LSUpdatePayload struct {
	layers.LSUpdate
	LSAs []LSAdvertisement
}

func (p LSUpdatePayload) Size() int {
	totalLen := 4
	for _, l := range p.LSAs {
		totalLen += l.Size()
	}
	return totalLen
}

func (p LSUpdatePayload) SerializeToSizedBuffer(b []byte) (err error) {
	if len(b) < p.Size() {
		return ErrBufferLengthTooShort
	}
	binary.BigEndian.PutUint32(b[0:4], p.NumOfLSAs)
	offset := 0
	for _, l := range p.LSAs {
		if err = l.SerializeToSizedBuffer(b[4+offset : 4+offset+l.Size()]); err != nil {
			return
		}
		offset += l.Size()
	}
	return
}

func (pt *LSUpdatePayload) parse() (err error) {
	pt.LSAs = make([]LSAdvertisement, 0, len(pt.LSUpdate.LSAs))
	for _, l := range pt.LSUpdate.LSAs {
		lsa := LSAdvertisement{LSA: l}
		if err = lsa.parse(); err != nil {
			return fmt.Errorf("err parse LSA: %w", err)
		}
		pt.LSAs = append(pt.LSAs, lsa)
	}
	return
}

type LSAcknowledgementPayload []LSAheader

func (p LSAcknowledgementPayload) Size() int {
	return LSAheader{}.Size() * len(p)
}

func (p LSAcknowledgementPayload) SerializeToSizedBuffer(b []byte) (err error) {
	if len(b) < p.Size() {
		return ErrBufferLengthTooShort
	}
	offset := 0
	for _, h := range p {
		if err = h.SerializeToSizedBuffer(b[offset : offset+h.Size()]); err != nil {
			return
		}
		offset += h.Size()
	}
	return
}

type LSAdvertisement struct {
	layers.LSA
	LSAheader
	Content LSAContent
}

func (pt *LSAdvertisement) parse() error {
	pt.LSAheader = LSAheader(pt.LSA.LSAheader)
	if int(pt.Length) < pt.LSAheader.Size() {
		return fmt.Errorf("LSA too short")
	}
	switch pt.LSType {
	case layers.RouterLSAtypeV2:
		lsa, err := pt.AsV2RouterLSA()
		if err != nil {
			return err
		}
		pt.Content = lsa.Content
	case layers.NetworkLSAtypeV2:
		lsa, err := pt.AsV2NetworkLSA()
		if err != nil {
			return err
		}
		pt.Content = lsa.Content
	case layers.SummaryLSANetworktypeV2:
		lsa, err := pt.AsV2SummaryLSAType3()
		if err != nil {
			return err
		}
		pt.Content = lsa.Content
	case layers.SummaryLSAASBRtypeV2:
		lsa, err := pt.AsV2SummaryLSAType4()
		if err != nil {
			return err
		}
		pt.Content = lsa.Content
	case layers.ASExternalLSAtypeV2:
		lsa, err := pt.AsV2ASExternalLSA()
		if err != nil {
			return err
		}
		pt.Content = lsa.Content
	default:
		return fmt.Errorf("LSA.LSType(%x) not implemented", pt.LSType)
	}
	return nil
}

func (p LSAdvertisement) Size() int {
	if p.Length > 0 {
		return int(p.Length)
	}
	return p.LSAheader.Size() + p.Content.Size()
}

func (p LSAdvertisement) SerializeToSizedBuffer(b []byte) (err error) {
	if len(b) < p.Size() || len(b) < p.LSAheader.Size() || len(b) < p.Content.Size() {
		return ErrBufferLengthTooShort
	}

	// fix length
	if p.LSAheader.Length <= 0 {
		p.LSAheader.Length = uint16(p.LSAheader.Size() + p.Content.Size())
	}
	if err = p.LSAheader.SerializeToSizedBuffer(b[0:p.LSAheader.Size()]); err != nil {
		return
	}
	if err = p.Content.SerializeToSizedBuffer(b[p.LSAheader.Size() : p.LSAheader.Size()+p.Content.Size()]); err != nil {
		return
	}
	// fix chksum
	if p.LSChecksum <= 0 {
		p.LSAheader.recalculateChecksum(b)
	}
	return
}

// Fletcher-16 checksum
func lsaChecksum(b []byte) uint16 {
	var (
		sum1, sum2 uint16 = 0, 0
	)
	for i := 0; i < len(b); i++ {
		sum1 = (sum1 + uint16(b[i])) % 255
		sum2 = (sum2 + sum1) % 255
	}
	return (sum2 << 8) | sum1
}

type LSAheader layers.LSAheader

func (p LSAheader) Size() int {
	return 20
}

func (p LSAheader) recalculateChecksum(b []byte) {
	// clear LS age before calculation
	clear(b[0:2])
	// clear chksum bytes
	clear(b[16:18])
	binary.BigEndian.PutUint16(b[16:18], lsaChecksum(b))
	// add back LS age
	binary.BigEndian.PutUint16(b[0:2], p.LSAge)
}

func (p LSAheader) SerializeToSizedBuffer(b []byte) error {
	if len(b) < p.Size() {
		return ErrBufferLengthTooShort
	}
	binary.BigEndian.PutUint16(b[0:2], p.LSAge)
	b[2] = p.LSOptions
	b[3] = uint8(p.LSType)
	binary.BigEndian.PutUint32(b[4:8], p.LinkStateID)
	binary.BigEndian.PutUint32(b[8:12], p.AdvRouter)
	binary.BigEndian.PutUint32(b[12:16], p.LSSeqNumber)
	binary.BigEndian.PutUint16(b[16:18], p.LSChecksum)
	binary.BigEndian.PutUint16(b[18:20], p.Length)
	return nil
}

type marshalable interface {
	Size() int
	SerializeToSizedBuffer(b []byte) error
}

type LSAContent interface {
	isLSAContent() // make it private
	marshalable
}

type rawLSA []byte

func (p rawLSA) isLSAContent() {}

func (p rawLSA) Size() int {
	return len(p)
}

func (p rawLSA) SerializeToSizedBuffer(b []byte) error {
	if len(b) < len(p) {
		return ErrBufferLengthTooShort
	}
	copy(b, p)
	return nil
}

func (v2 *OSPFv2Packet[T]) packetErr(format string, args ...interface{}) error {
	return fmt.Errorf("malformed ospfv2 %s packet: "+format, append([]interface{}{v2.Type}, args...)...)
}

func ipPacketChecksum(bytes []byte) uint16 {
	// Compute ipPacketChecksum
	var csum uint32
	for i := 0; i < len(bytes); i += 2 {
		csum += uint32(bytes[i]) << 8
		csum += uint32(bytes[i+1])
	}
	for {
		// Break when sum is less or equals to 0xFFFF
		if csum <= 65535 {
			break
		}
		// Add carry to the sum
		csum = (csum >> 16) + uint32(uint16(csum))
	}
	// Flip all the bits
	return ^uint16(csum)
}

// SerializeTo writes the serialized form of this layer into the
// SerializationBuffer, implementing gopacket.SerializableLayer.
func (v2 *OSPFv2Packet[T]) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) (err error) {
	// proc header at last
	defer func() {
		if err != nil {
			// some err occurred before, simply return it
			return
		}
		var h []byte
		h, err = b.PrependBytes(24) // per RFC2328 A.3.1
		if err != nil {
			return
		}
		// header manipulation
		h[0] = v2.Version
		h[1] = uint8(v2.Type)
		if opts.FixLengths {
			v2.PacketLength = uint16(len(b.Bytes()))
		}
		binary.BigEndian.PutUint16(h[2:4], v2.PacketLength)
		binary.BigEndian.PutUint32(h[4:8], v2.RouterID)
		binary.BigEndian.PutUint32(h[8:12], v2.AreaID)
		binary.BigEndian.PutUint16(h[14:16], v2.AuType)
		if opts.ComputeChecksums {
			// clear ipPacketChecksum bytes
			clear(h[12:14])
			// clear authentication bytes
			clear(h[16:24])
			v2.Checksum = ipPacketChecksum(b.Bytes())
		}
		binary.BigEndian.PutUint16(h[12:14], v2.Checksum)
		// ipPacketChecksum calculation must exclude 64bit authentication bytes.
		// so make it last set.
		binary.BigEndian.PutUint64(h[16:24], v2.Authentication)
	}()

	// proc payload first
	p, err := b.AppendBytes(v2.Content.Size())
	if err != nil {
		return
	}
	return v2.Content.SerializeToSizedBuffer(p)
}
