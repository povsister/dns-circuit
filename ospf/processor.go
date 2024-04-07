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
	logDebug("Got OSPFv%d %s\nRouterId: %v AreaId:%v\n%+v\n",
		hello.Version, hello.Type, hello.RouterID, hello.AreaID, hello.Content)

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
	logDebug("Got OSPFv%d %s\nRouterId: %v AreaId: %v\n%+v\n", dd.Version, dd.Type, dd.RouterID, dd.AreaID,
		dd.Content)

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
		// Exchange), the packet's Options field should be recorded in
		// the neighbor structure's Neighbor Options field.
		negotiationDone := func() {
			neighbor.NeighborOptions = packet.BitOption(dd.Content.Options)
			if neighbor.IsMaster {
				// im slave. prepare for dd exchange
				neighbor.consumeEvent(NbEvNegotiationDone)
				logDebug("Wait for first master sync")
				neighbor.slavePrepareDDExchange()
			} else {
				// im master. must wait for slave echo for acknowledgement.
				// then starting dd exchange.
				neighbor.consumeEvent(NbEvNegotiationDone)
				logDebug("Sending out first DD exchange")
				neighbor.masterStartDDExchange()
			}
		}
		flags := packet.BitOption(dd.Content.Flags)
		if flags.IsBitSet(packet.DDOptionIbit) && flags.IsBitSet(packet.DDOptionMbit) &&
			flags.IsBitSet(packet.DDOptionMSbit) && len(dd.Content.LSAinfo) <= 0 &&
			neighbor.NeighborId > i.Area.ins.RouterId {
			// The initialize(I), more (M) and master(MS) bits are set,
			// the contents of the packet are empty, and the neighbor's
			// Router ID is larger than the router's own.  In this case
			// the router is now Slave.  Set the master/slave bit to
			// slave, and set the neighbor data structure's DD sequence
			// number to that specified by the master.
			logDebug("ExStart negotiation: i am slave")
			neighbor.IsMaster = true
			neighbor.DDSeqNumber.Store(dd.Content.DDSeqNumber)
			negotiationDone()
		} else if !flags.IsBitSet(packet.DDOptionIbit) && !flags.IsBitSet(packet.DDOptionMSbit) &&
			dd.Content.DDSeqNumber == neighbor.DDSeqNumber.Load() && neighbor.NeighborId < i.Area.ins.RouterId {
			// The initialize(I) and master(MS) bits are off, the
			// packet's DD sequence number equals the neighbor data
			// structure's DD sequence number (indicating
			// acknowledgment) and the neighbor's Router ID is smaller
			// than the router's own.  In this case the router is
			// Master.
			logDebug("ExStart negotiation: i am master")
			neighbor.IsMaster = false
			negotiationDone()
		} else {
			// Otherwise, the packet should be ignored.
			return
		}
		// The packet should be accepted as next in sequence and processed
		// further (see below).
		//fallthrough
	case NeighborExchange:
		// check if packet is duplicated
		if lastDD, isDup := neighbor.isDuplicatedDD(dd); isDup {
			if !neighbor.IsMaster {
				// im master. silently discard duplicated packets
				return
			}
			// im slave. repeating last dd
			neighbor.echoDDWithPossibleRetransmission(lastDD)
			return
		}
		flags := packet.BitOption(dd.Content.Flags)
		if flags.IsBitSet(packet.DDOptionMSbit) != neighbor.IsMaster ||
			flags.IsBitSet(packet.DDOptionIbit) ||
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
			if !packet.BitOption(dd.Content.Flags).IsBitSet(packet.DDOptionMbit) && allDDSent {
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
				IsBitSet(packet.DDOptionMbit)); !needWaitForAck {
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
		logDebug("Ignored DatabaseDesc from RouterId: %v AreId: %v: neighbor state mismatch",
			dd.RouterID, dd.AreaID)
	}
}

func (a *Area) procLSR(i *Interface, h *ipv4.Header, lsr *packet.OSPFv2Packet[packet.LSRequestPayload]) {

}

func (a *Area) procLSU(i *Interface, h *ipv4.Header, lsu *packet.OSPFv2Packet[packet.LSUpdatePayload]) {

}

func (a *Area) procLSAck(i *Interface, h *ipv4.Header, lsack *packet.OSPFv2Packet[packet.LSAcknowledgementPayload]) {

}
