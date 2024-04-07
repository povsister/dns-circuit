package packet

type BitOption uint8

func (b BitOption) SetBit(bits ...uint8) BitOption {
	ret := b
	for _, bit := range bits {
		ret = ret | (1 << bit)
	}
	return ret
}

func (b BitOption) ClearBit(bits ...uint8) BitOption {
	ret := b
	for _, bit := range bits {
		ret = ret & ^(1 << bit)
	}
	return ret
}

func (b BitOption) IsBitSet(bit uint8) bool {
	return b>>bit&1 == 1
}

const (
	//	   The OSPF Options field is present in OSPF Hello packets, Database
	//	   Description packets and all LSAs.  The Options field enables OSPF
	//	   routers to support (or not support) optional capabilities, and to
	//	   communicate their capability level to other OSPF routers.  Through
	//	   this mechanism routers of differing capabilities can be mixed within
	//	   an OSPF routing domain.
	//
	//	   When used in Hello packets, the Options field allows a router to
	//	   reject a neighbor because of a capability mismatch.  Alternatively,
	//	   when capabilities are exchanged in Database Description packets a
	//	   router can choose not to forward certain LSAs to a neighbor because
	//	   of its reduced functionality.  Lastly, listing capabilities in LSAs
	//	   allows routers to forward traffic around reduced functionality
	//	   routers, by excluding them from parts of the routing table
	//	   calculation.
	//
	//	   Five bits of the OSPF Options field have been assigned, although
	//	   only one (the E-bit) is described completely by this memo. Each bit
	//	   is described briefly below. Routers should reset (i.e.  clear)
	//	   unrecognized bits in the Options field when sending Hello packets or
	//	   Database Description packets and when originating LSAs. Conversely,
	//	   routers encountering unrecognized Options bits in received Hello
	//	   Packets, Database Description packets or LSAs should ignore the
	//	   capability and process the packet/LSA normally.
	//
	//	                      +------------------------------------+
	//	                      | * | * | DC | EA | N/P | MC | E | * |
	//	                      +------------------------------------+
	//
	//	                            The Options field

	// CapabilityEbit This bit describes the way AS-external-LSAs are flooded, as
	//        described in Sections 3.6, 9.5, 10.8 and 12.1.2 of this memo.
	CapabilityEbit = 1
	// CapabilityMCbit This bit describes whether IP multicast datagrams are forwarded
	//        according to the specifications in [Ref18].
	CapabilityMCbit = 2
	// CapabilityNPbit This bit describes the handling of Type-7 LSAs, as specified in
	//        [Ref19].
	CapabilityNPbit = 3
	// CapabilityEAbit This bit describes the router's willingness to receive and
	//        forward External-Attributes-LSAs, as specified in [Ref20].
	CapabilityEAbit = 4
	// CapabilityDCbit This bit describes the router's handling of demand circuits, as
	//        specified in [Ref21].
	CapabilityDCbit = 5
)

const (
	// 	     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//       |         Interface MTU         |    Options    |0|0|0|0|0|I|M|MS
	//       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

	// DDOptionMSbit The Master/Slave bit.  When set to 1, it indicates that the
	//        router is the master during the Database Exchange process.
	//        Otherwise, the router is the slave.
	DDOptionMSbit = 0
	// DDOptionMbit The More bit.  When set to 1, it indicates that more Database
	//        Description Packets are to follow.
	DDOptionMbit = 1
	// DDOptionIbit The Init bit.  When set to 1, this packet is the first in the
	//        sequence of Database Description Packets.
	DDOptionIbit = 2
)
