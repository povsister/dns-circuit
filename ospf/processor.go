package ospf

import (
	"github.com/google/gopacket/layers"
	"golang.org/x/net/ipv4"

	"github.com/povsister/dns-circuit/ospf/packet"
)

func (i *Interface) doParsedMsgProcessing(h *ipv4.Header, op *packet.LayerOSPFv2) {
	switch op.Type {
	case layers.OSPFHello:
		hello, err := op.AsHello()
		if err != nil {
			logErr("unexpected non Hello: %v", err)
			return
		}
		i.Area.procHello(i, h, hello)
	case layers.OSPFDatabaseDescription:
		dbd, err := op.AsDbDescription()
		if err != nil {
			logErr("unexpected non DatabaseDesc: %v", err)
			return
		}
		i.Area.procDatabaseDesc(i, h, dbd)
	case layers.OSPFLinkStateRequest:
		lsr, err := op.AsLSRequest()
		if err != nil {
			logErr("unexpected non LSR: %v", err)
			return
		}
		i.Area.procLSR(i, h, lsr)
	case layers.OSPFLinkStateUpdate:
		lsu, err := op.AsLSUpdate()
		if err != nil {
			logErr("unexpected non LSU: %v", err)
			return
		}
		i.Area.procLSU(i, h, lsu)
	case layers.OSPFLinkStateAcknowledgment:
		lsack, err := op.AsLSAcknowledgment()
		if err != nil {
			logErr("unexpected non LSAck: %v", err)
			return
		}
		i.Area.procLSAck(i, h, lsack)
	default:
		logErr("unknown OSPF packet type: %v", op.Type)
	}
}

func (a *Area) procHello(i *Interface, h *ipv4.Header, hello *packet.OSPFv2Packet[packet.HelloPayloadV2]) {
	logDebug("Got OSPFv%d %s(%d)\nRouterId: %v AreaId:%v\n%+v",
		hello.Version, hello.Type, hello.PacketLength, hello.RouterID, hello.AreaID, hello.Content)

	// pre-checks
	if hello.Content.HelloInterval != i.HelloInterval || hello.Content.RouterDeadInterval != i.RouterDeadInterval ||
		(i.shouldCheckNeighborNetworkMask() && ipv4MaskToUint32(i.Address.Mask) != hello.Content.NetworkMask) {
		logDebug("Rejected Hello from RouterId: %v AreId: %v: pre-check failure", hello.RouterID, hello.AreaID)
		return
	}

	neighborId := hello.RouterID
	neighbor, ok := i.getNeighbor(neighborId)
	if !ok {
		neighbor = i.addNeighbor(h, hello)
	}
	// Each Hello Packet causes the neighbor state machine to be
	// executed with the event HelloReceived.
	neighbor.consumeEvent(NbEvHelloReceived)

	if i.shouldHaveDR() {
		// Then the list of neighbors contained in the Hello Packet is examined.
		isMySelfSeen := false
		for _, seenNbs := range hello.Content.NeighborID {
			if seenNbs == a.ins.RouterId {
				isMySelfSeen = true
				break
			}
		}
		if isMySelfSeen {
			// for the reason that rt priority is always 0.
			// just some handy addon
			i.DR.Store(neighbor.NeighborsDR)
			i.BDR.Store(neighbor.NeighborsBDR)
			// If the router itself appears in this list, the
			// neighbor state machine should be executed with the event 2-WayReceived.
			neighbor.consumeEvent(NbEv2WayReceived)
		} else {
			// Otherwise, the neighbor state machine should
			// be executed with the event 1-WayReceived, and the processing of the packet stops.
			neighbor.consumeEvent(NbEv1Way)
			return
		}
		// Next, if a change in the neighbor's Router Priority field
		// was noted, the receiving interface's state machine is
		// scheduled with the event NeighborChange.
		if neighbor.NeighborPriority != hello.Content.RtrPriority {
			i.consumeEvent(IfEvNeighborChange)
		}
		// If the neighbor is both declaring itself to be Designated
		// Router (Hello Packet's Designated Router field = Neighbor IP
		// address) and the Backup Designated Router field in the
		// packet is equal to 0.0.0.0 and the receiving interface is in
		// state Waiting, the receiving interface's state machine is
		// scheduled with the event BackupSeen.
		if i.currState() == InterfaceWaiting && neighborId == hello.Content.DesignatedRouterID &&
			hello.Content.BackupDesignatedRouterID == 0 {
			i.consumeEvent(IfEvBackupSeen)
		} else if neighborId == hello.Content.DesignatedRouterID &&
			neighbor.NeighborsDR != neighborId {
			// Otherwise, if the neighbor is declaring itself to be Designated Router and it
			// had not previously, or the neighbor is not declaring itself
			// Designated Router where it had previously, the receiving
			// interface's state machine is scheduled with the event NeighborChange.
			i.consumeEvent(IfEvNeighborChange)
		}
		// If the neighbor is declaring itself to be Backup Designated
		// Router (Hello Packet's Backup Designated Router field =
		// Neighbor IP address) and the receiving interface is in state
		// Waiting, the receiving interface's state machine is
		// scheduled with the event BackupSeen.
		if i.currState() == InterfaceWaiting && neighborId == hello.Content.BackupDesignatedRouterID {
			i.consumeEvent(IfEvBackupSeen)
		} else if neighborId == hello.Content.BackupDesignatedRouterID &&
			neighbor.NeighborsBDR != neighborId {
			// Otherwise, if the neighbor is declaring itself to be Backup Designated Router
			// and it had not previously, or the neighbor is not declaring
			// itself Backup Designated Router where it had previously, the
			// receiving interface's state machine is scheduled with the
			// event NeighborChange.
			i.consumeEvent(IfEvNeighborChange)
		}
	}
}

func (a *Area) procDatabaseDesc(i *Interface, h *ipv4.Header, dd *packet.OSPFv2Packet[packet.DbDescPayload]) {
	logDebug("Got OSPFv%d %s(%d)\nRouterId: %v AreaId: %v\n%+v", dd.Version, dd.Type, dd.PacketLength,
		dd.RouterID, dd.AreaID, dd.Content)

	neighborId := dd.RouterID
	neighbor, ok := i.getNeighbor(neighborId)
	if !ok {
		logDebug("Rejected DatabaseDesc from RouterId: %v AreId: %v: no neighbor found", dd.RouterID, dd.AreaID)
		return
	}
	// If the Interface MTU field in the Database Description packet
	// indicates an IP datagram size that is larger than the router can
	// accept on the receiving interface without fragmentation, the
	// Database Description packet is rejected.
	if dd.Content.InterfaceMTU > i.MTU {
		logDebug("Rejected DatabaseDesc from RouterId: %v AreId: %v: neighbor MTU(%d) > InterfaceMTU(%d)",
			dd.RouterID, dd.AreaID, dd.Content.InterfaceMTU, i.MTU)
		return
	}
	switch neighbor.currState() {
	case Neighbor2Way:
		// The packet should be ignored.  Database Description Packets
		// are used only for the purpose of bringing up adjacencies.
	case NeighborInit:
		neighbor.consumeEvent(NbEv2WayReceived)
		if neighbor.currState() != NeighborExStart {
			return
		}
		// If the new state is ExStart, the processing of the current packet should then
		// continue in this new state by falling through to case ExStart below.
		fallthrough
	case NeighborExStart:
		// If the received packet matches one of the following cases,
		// then the neighbor state machine should be executed with the
		// event NegotiationDone (causing the state to transition to
		// Exchange)
		flags := packet.BitOption(dd.Content.Flags)
		if flags.IsBitSet(packet.DDFlagIbit) && flags.IsBitSet(packet.DDFlagMbit) &&
			flags.IsBitSet(packet.DDFlagMSbit) && len(dd.Content.LSAinfo) <= 0 &&
			neighbor.NeighborId > i.Area.ins.RouterId {
			// The initialize(I), more (M) and master(MS) bits are set,
			// the contents of the packet are empty, and the neighbor's
			// Router ID is larger than the router's own.  In this case
			// the router is now Slave.  Set the master/slave bit to
			// slave, and set the neighbor data structure's DD sequence
			// number to that specified by the master.
			logDebug("ExStart negotiation result: I am slave")
			neighbor.IsMaster = true
			neighbor.DDSeqNumber.Store(dd.Content.DDSeqNumber)
		} else if !flags.IsBitSet(packet.DDFlagIbit) && !flags.IsBitSet(packet.DDFlagMSbit) &&
			dd.Content.DDSeqNumber == neighbor.DDSeqNumber.Load() && neighbor.NeighborId < i.Area.ins.RouterId {
			// The initialize(I) and master(MS) bits are off, the
			// packet's DD sequence number equals the neighbor data
			// structure's DD sequence number (indicating
			// acknowledgment) and the neighbor's Router ID is smaller
			// than the router's own.  In this case the router is
			// Master.
			logDebug("ExStart negotiation result: I am master")
			neighbor.IsMaster = false
		} else {
			// Otherwise, the packet should be ignored.
			return
		}
		// NegotiationDone here.
		neighbor.consumeEvent(NbEvNegotiationDone)
		// if the NegotiationDone event fired.
		// the packet's Options field should be recorded in the
		// neighbor structure's Neighbor Options field.
		neighbor.NeighborOptions = packet.BitOption(dd.Content.Options)
		neighbor.saveLastReceivedDD(dd)
		if neighbor.IsMaster {
			// im slave. prepare for dd exchange
			logDebug("Slave sending out negotiation result ack and wait for first master sync")
			// note that the dd echo is sent by fallthrough statement
			neighbor.slavePrepareDDExchange()
		} else {
			// im master. starting dd exchange.
			neighbor.consumeEvent(NbEvNegotiationDone)
			logDebug("Master sending out first DD exchange because negotiation result ack received")
			neighbor.masterStartDDExchange(dd)
		}
		// The packet should be accepted as next in sequence and processed
		// further (see below).
		fallthrough
	case NeighborExchange:
		// check if packet is duplicated
		if lastDD, isDup := neighbor.isDuplicatedDD(dd); isDup {
			if !neighbor.IsMaster {
				// im master. silently discard duplicated packets
				return
			}
			// im slave. repeating last dd.
			// This also ack the master state.
			neighbor.echoDDWithPossibleRetransmission(lastDD)
			return
		}
		flags := packet.BitOption(dd.Content.Flags)
		if flags.IsBitSet(packet.DDFlagMSbit) != neighbor.IsMaster ||
			flags.IsBitSet(packet.DDFlagIbit) ||
			packet.BitOption(dd.Content.Options) != neighbor.NeighborOptions {
			// If the state of the MS-bit is inconsistent with the
			// master/slave state of the connection, generate the
			// neighbor event SeqNumberMismatch and stop processing the packet.
			// If the initialize(I) bit is set, generate the neighbor
			// event SeqNumberMismatch and stop processing the packet.
			// If the packet's Options field indicates a different set
			// of optional OSPF capabilities than were previously
			// received from the neighbor (recorded in the Neighbor
			// Options field of the neighbor structure), generate the
			// neighbor event SeqNumberMismatch and stop processing the
			// packet.
			neighbor.consumeEvent(NbEvSeqNumberMismatch)
			return
		}
		// Database Description packets must be processed in
		// sequence, as indicated by the packets' DD sequence
		// numbers. If the router is master, the next packet
		// received should have DD sequence number equal to the DD
		// sequence number in the neighbor data structure. If the
		// router is slave, the next packet received should have DD
		// sequence number equal to one more than the DD sequence
		// number stored in the neighbor data structure. In either
		// case, if the packet is the next in sequence it should be
		// accepted and its contents processed as specified below.
		// Else, generate the neighbor event SeqNumberMismatch and
		// stop processing the packet.
		expectedDDSeqNum := neighbor.DDSeqNumber.Load()
		if neighbor.IsMaster {
			// im slave. expecting 1 bigger than existing dd num
			expectedDDSeqNum += 1
		}
		if expectedDDSeqNum != dd.Content.DDSeqNumber {
			neighbor.consumeEvent(NbEvSeqNumberMismatch)
			return
		}
		// record last accepted dd packet
		neighbor.saveLastReceivedDD(dd)
		if neighbor.IsMaster {
			// im slave. save the dd seq number offered by master
			neighbor.DDSeqNumber.Store(dd.Content.DDSeqNumber)
			// echo the dd from master and send dd of my own.
			// then process the dd from master
			allDDSent := neighbor.slaveDDEchoAndExchange(dd)
			neighbor.parseDD(dd)
			if !packet.BitOption(dd.Content.Flags).IsBitSet(packet.DDFlagMbit) && allDDSent {
				// no more DD packets from master.
				// and all local dd has been sent.
				// This marks dd exchange done.
				neighbor.consumeEvent(NbEvExchangeDone)
			}
		} else {
			// im master. this is a dd echo packet with summary.
			// parse it and try continue sending next dd
			neighbor.parseDD(dd)
			if needWaitForAck := neighbor.masterContinueDDExchange(packet.BitOption(dd.Content.Flags).
				IsBitSet(packet.DDFlagMbit)); !needWaitForAck {
				// no dd echo need(no dd packet has been sent or slave has finished DD, too).
				// indicating it is the last dd packet echo.
				// This marks the end of dd packet send process.
				neighbor.consumeEvent(NbEvExchangeDone)
			}
		}

	case NeighborLoading, NeighborFull:
		// In this state, the router has sent and received an entire
		//            sequence of Database Description Packets.  The only packets
		//            received should be duplicates (see above).  In particular,
		//            the packet's Options field should match the set of optional
		//            OSPF capabilities previously indicated by the neighbor
		//            (stored in the neighbor structure's Neighbor Options field).
		//            Any other packets received, including the reception of a
		//            packet with the Initialize(I) bit set, should generate the
		//            neighbor event SeqNumberMismatch.[8] Duplicates should be
		//            discarded by the master.  The slave must respond to
		//            duplicates by repeating the last Database Description packet
		//            that it had sent.
		if lastDD, isDup := neighbor.isDuplicatedDD(dd); isDup {
			// duplicated packets received.
			if neighbor.IsMaster {
				// im slave, repeating last dd
				neighbor.echoDDWithPossibleRetransmission(lastDD)
			}
		} else {
			// non-duplicated packets
			neighbor.consumeEvent(NbEvSeqNumberMismatch)
		}
	default:
		logDebug("Ignored DatabaseDesc from RouterId: %v AreaId: %v: neighbor state mismatch",
			dd.RouterID, dd.AreaID)
	}
}

func (a *Area) procLSR(i *Interface, h *ipv4.Header, lsr *packet.OSPFv2Packet[packet.LSRequestPayload]) {
	logDebug("Got OSPFv%d %s(%d)\nRouterId: %v AreaId: %v\n%+v", lsr.Version, lsr.Type, lsr.PacketLength,
		lsr.RouterID, lsr.AreaID, lsr.Content)

	neighbor, ok := i.getNeighbor(lsr.RouterID)
	if !ok {
		return
	}
	// Received Link State Request Packets
	// specify a list of LSAs that the neighbor wishes to receive.
	switch neighbor.currState() {
	// Link State Request Packets should be accepted when the neighbor
	// is in states Exchange, Loading, or Full.
	case NeighborExchange, NeighborLoading, NeighborFull:
		// If an LSA cannot be found in the database,
		// something has gone wrong with the Database Exchange process, and
		// neighbor event BadLSReq should be generated.
		if err := a.respondLSReqWithLSU(neighbor, lsr.Content); err != nil {
			logErr("Wrong LSRequest from RouterId: %v AreaId: %v: %v", neighbor.NeighborId, a.AreaId, err)
			neighbor.consumeEvent(NbEvBadLSReq)
		}
	default:
		// In all other states Link State Request Packets should be ignored.
		return
	}
}

func (a *Area) procLSU(i *Interface, h *ipv4.Header, lsu *packet.OSPFv2Packet[packet.LSUpdatePayload]) {
	logDebug("Got OSPFv%d %s(%d)\nRouterId: %v AreaId: %v\n%+v", lsu.Version, lsu.Type, lsu.PacketLength,
		lsu.RouterID, lsu.AreaID, lsu.Content)

	neighbor, ok := i.getNeighbor(lsu.RouterID)
	if !ok {
		return
	}
	// If the neighbor is in a lesser state than Exchange, the packet should
	// be dropped without further processing.
	if neighbor.currState() < NeighborExchange {
		return
	}

	// All types of LSAs, other than AS-external-LSAs, are associated with
	// a specific area.  However, LSAs do not contain an area field.  An
	// LSA's area must be deduced from the Link State Update packet header.

	acks := make([]packet.LSAheader, 0, lsu.Content.NumOfLSAs)
	for _, l := range lsu.Content.LSAs {
		err := l.ValidateLSA()
		if err != nil {
			logErr("Wrong LSA from RouterId: %v AreaId: %v: %v", neighbor.NeighborId, a.AreaId)
			continue
		}
		// if this is an AS-external-LSA (LS type = 5), and the area
		//        has been configured as a stub area, discard the LSA and get the
		//        next one from the Link State Update Packet.  AS-external-LSAs
		//        are not flooded into/throughout stub areas
		if !a.ExternalRoutingCapability && l.LSType == layers.ASExternalLSAtypeV2 {
			continue
		}

		fromLSDb, _, existInLSDB := a.lsDbGetLSAByIdentity(l.GetLSAIdentity(), false)
		// if the LSA's LS age is equal to MaxAge, and there is
		//        currently no instance of the LSA in the router's link state
		//        database, and none of router's neighbors are in states Exchange
		//        or Loading, then take the following actions: a) Acknowledge the
		//        receipt of the LSA by sending a Link State Acknowledgment packet
		//        back to the sending neighbor (see Section 13.5), and b) Discard
		//        the LSA and examine the next LSA (if any) listed in the Link
		//        State Update packet.
		if l.LSAge == packet.MaxAge && !existInLSDB &&
			!a.hasNeighborStateIN(NeighborExchange, NeighborLoading) {
			acks = append(acks, l.GetLSAck())
			continue
		}

		// Otherwise, find the instance of this LSA that is currently
		//        contained in the router's link state database.  If there is no
		//        database copy, or the received LSA is more recent than the
		//        database copy (see Section 13.1 below for the determination of
		//        which LSA is more recent) the following steps must be performed:
		if !existInLSDB || l.IsMoreRecentThan(fromLSDb) {
			// (a) If there is already a database copy, and if the database
			//            copy was received via flooding and installed less than
			//            MinLSArrival seconds ago, discard the new LSA (without
			//            acknowledging it) and examine the next LSA (if any) listed
			//            in the Link State Update packet.

			// TODO:

			// (b) Otherwise immediately flood the new LSA out some subset of
			//            the router's interfaces (see Section 13.3).  In some cases
			//            (e.g., the state of the receiving interface is DR and the
			//            LSA was received from a router other than the Backup DR) the
			//            LSA will be flooded back out the receiving interface.  This
			//            occurrence should be noted for later use by the
			//            acknowledgment process (Section 13.5).

			// (c) Remove the current database copy from all neighbors' Link
			//            state retransmission lists.

			// (d) Install the new LSA in the link state database (replacing
			//            the current database copy).  This may cause the routing
			//            table calculation to be scheduled.  In addition, timestamp
			//            the new LSA with the current time (i.e., the time it was
			//            received).  The flooding procedure cannot overwrite the
			//            newly installed LSA until MinLSArrival seconds have elapsed.
			//            The LSA installation process is discussed further in Section
			//            13.2.

			// (e) Possibly acknowledge the receipt of the LSA by sending a
			//            Link State Acknowledgment packet back out the receiving
			//            interface.  This is explained below in Section 13.5.

			// (f) If this new LSA indicates that it was originated by the
			//            receiving router itself (i.e., is considered a self-
			//            originated LSA), the router must take special action, either
			//            updating the LSA or in some cases flushing it from the
			//            routing domain. For a description of how self-originated
			//            LSAs are detected and subsequently handled, see Section
			//            13.4.

		} else if neighbor.isInLSReqList(l.GetLSAIdentity()) {
			// Else, if there is an instance of the LSA on the sending
			//        neighbor's Link state request list, an error has occurred in the
			//        Database Exchange process.  In this case, restart the Database
			//        Exchange process by generating the neighbor event BadLSReq for
			//        the sending neighbor and stop processing the Link State Update
			//        packet.
			neighbor.consumeEvent(NbEvBadLSReq)
			return

		} else if existInLSDB && !l.IsMoreRecentThan(fromLSDb) && !fromLSDb.IsMoreRecentThan(l.LSAheader) {
			// Else, if the received LSA is the same instance as the database
			//        copy (i.e., neither one is more recent) the following two steps
			//        should be performed:

			// (a) If the LSA is listed in the Link state retransmission list
			//            for the receiving adjacency, the router itself is expecting
			//            an acknowledgment for this LSA.  The router should treat the
			//            received LSA as an acknowledgment by removing the LSA from
			//            the Link state retransmission list.  This is termed an
			//            "implied acknowledgment".  Its occurrence should be noted
			//            for later use by the acknowledgment process (Section 13.5).

			// (b) Possibly acknowledge the receipt of the LSA by sending a
			//            Link State Acknowledgment packet back out the receiving
			//            interface.  This is explained below in Section 13.5.

			// TODO:

		} else if existInLSDB && fromLSDb.IsMoreRecentThan(l.LSAheader) {
			// Else, the database copy is more recent.  If the database copy
			//        has LS age equal to MaxAge and LS sequence number equal to
			//        MaxSequenceNumber, simply discard the received LSA without
			//        acknowledging it. (In this case, the LSA's LS sequence number is
			//        wrapping, and the MaxSequenceNumber LSA must be completely
			//        flushed before any new LSA instance can be introduced).
			//        Otherwise, as long as the database copy has not been sent in a
			//        Link State Update within the last MinLSArrival seconds, send the
			//        database copy back to the sending neighbor, encapsulated within
			//        a Link State Update Packet. The Link State Update Packet should
			//        be sent directly to the neighbor. In so doing, do not put the
			//        database copy of the LSA on the neighbor's link state
			//        retransmission list, and do not acknowledge the received (less
			//        recent) LSA instance.

			// TODO:
		}
	}
	if len(acks) > 0 {
		neighbor.ackLSAdvertisements(acks)
	}
}

func (a *Area) procLSAck(i *Interface, h *ipv4.Header, lsack *packet.OSPFv2Packet[packet.LSAcknowledgementPayload]) {
	logDebug("Got OSPFv%d %s(%d)\nRouterId: %v AreaId: %v\n%+v", lsack.Version, lsack.Type, lsack.PacketLength,
		lsack.RouterID, lsack.AreaID, lsack.Content)

	neighbor, ok := i.getNeighbor(lsack.RouterID)
	if !ok {
		return
	}
	// If this neighbor is in a lesser state than
	// Exchange, the Link State Acknowledgment packet is discarded.
	if neighbor.currState() < NeighborExchange {
		return
	}

	invalidAcks := neighbor.tryEmptyLSRetransmissionListByAck(lsack)
	if len(invalidAcks) > 0 {
		logWarn("Wrong LSAck from RouterId: %v AreaId: %v: \n%+v", neighbor.NeighborId, a.AreaId,
			invalidAcks)
	}
}
