package ospf

import (
	"math"
	"net"
	"time"

	"github.com/google/gopacket/layers"

	"github.com/povsister/dns-circuit/ospf/packet"
)

type NeighborState int

const (
	// NeighborDown This is the initial state of a neighbor conversation.  It
	//            indicates that there has been no recent information received
	//            from the neighbor.  On NBMA networks, Hello packets may
	//            still be sent to "Down" neighbors, although at a reduced
	//            frequency (see Section 9.5.1).
	NeighborDown NeighborState = iota
	// NeighborAttempt This state is only valid for neighbors attached to NBMA
	//            networks.  It indicates that no recent information has been
	//            received from the neighbor, but that a more concerted effort
	//            should be made to contact the neighbor.  This is done by
	//            sending the neighbor Hello packets at intervals of
	//            HelloInterval (see Section 9.5.1).
	NeighborAttempt
	// NeighborInit In this state, an Hello packet has recently been seen from
	//            the neighbor.  However, bidirectional communication has not
	//            yet been established with the neighbor (i.e., the router
	//            itself did not appear in the neighbor's Hello packet).  All
	//            neighbors in this state (or higher) are listed in the Hello
	//            packets sent from the associated interface.
	NeighborInit
	// Neighbor2Way In this state, communication between the two routers is
	//            bidirectional.  This has been assured by the operation of
	//            the Hello Protocol.  This is the most advanced state short
	//            of beginning adjacency establishment.  The (Backup)
	//            Designated Router is selected from the set of neighbors in
	//            state 2-Way or greater.
	Neighbor2Way
	// NeighborExStart This is the first step in creating an adjacency between the
	//            two neighboring routers.  The goal of this step is to decide
	//            which router is the master, and to decide upon the initial
	//            DD sequence number.  Neighbor conversations in this state or
	//            greater are called adjacencies.
	NeighborExStart
	// NeighborExchange In this state the router is describing its entire link state
	//            database by sending Database Description packets to the
	//            neighbor.  Each Database Description Packet has a DD
	//            sequence number, and is explicitly acknowledged.  Only one
	//            Database Description Packet is allowed outstanding at any
	//            one time.  In this state, Link State Request Packets may
	//            also be sent asking for the neighbor's more recent LSAs.
	//            All adjacencies in Exchange state or greater are used by the
	//            flooding procedure.  In fact, these adjacencies are fully
	//            capable of transmitting and receiving all types of OSPF
	//            routing protocol packets.
	NeighborExchange
	// NeighborLoading In this state, Link State Request packets are sent to the
	//            neighbor asking for the more recent LSAs that have been
	//            discovered (but not yet received) in the Exchange state.
	NeighborLoading
	// NeighborFull In this state, the neighboring routers are fully adjacent.
	//            These adjacencies will now appear in router-LSAs and
	//            network-LSAs.
	NeighborFull
)

type Neighbor struct {
	lastSeen time.Time
	i        *Interface

	// The functional level of the neighbor conversation.  This is
	//        described in more detail in Section 10.1.
	State NeighborState
	// A single shot timer whose firing indicates that no Hello Packet
	//        has been seen from this neighbor recently.  The length of the
	//        timer is RouterDeadInterval seconds.
	InactivityTimer *time.Timer
	// When the two neighbors are exchanging databases, they form a
	//        master/slave relationship.  The master sends the first Database
	//        Description Packet, and is the only part that is allowed to
	//        retransmit.  The slave can only respond to the master's Database
	//        Description Packets.  The master/slave relationship is
	//        negotiated in state ExStart.
	IsMaster bool
	// The DD Sequence number of the Database Description packet that
	//        is currently being sent to the neighbor.
	DDSeqNumber uint32

	// The initialize(I), more (M) and master(MS) bits, Options field,
	//        and DD sequence number contained in the last Database
	//        Description packet received from the neighbor. Used to determine
	//        whether the next Database Description packet received from the
	//        neighbor is a duplicate.
	LastReceivedDDPacket *packet.OSPFv2Packet[packet.DbDescPayload]

	NeighborId uint32
	// The Router Priority of the neighboring router.  Contained in the
	//        neighbor's Hello packets, this item is used when selecting the
	//        Designated Router for the attached network.
	NeighborPriority uint8

	// The IP address of the neighboring router's interface to the
	//        attached network.  Used as the Destination IP address when
	//        protocol packets are sent as unicasts along this adjacency.
	//        Also used in router-LSAs as the Link ID for the attached network
	//        if the neighboring router is selected to be Designated Router
	//        (see Section 12.4.1).  The Neighbor IP address is learned when
	//        Hello packets are received from the neighbor.  For virtual
	//        links, the Neighbor IP address is learned during the routing
	//        table build process (see Section 15).
	NeighborAddress net.IP
	// The optional OSPF capabilities supported by the neighbor.
	//        Learned during the Database Exchange process (see Section 10.6).
	//        The neighbor's optional OSPF capabilities are also listed in its
	//        Hello packets.  This enables received Hello Packets to be
	//        rejected (i.e., neighbor relationships will not even start to
	//        form) if there is a mismatch in certain crucial OSPF
	//        capabilities (see Section 10.5).  The optional OSPF capabilities
	//        are documented in Section 4.5.
	NeighborOptions packet.BitOption
	// The neighbor's idea of the Designated Router.  If this is the
	//        neighbor itself, this is important in the local calculation of
	//        the Designated Router.  Defined only on broadcast and NBMA
	//        networks.
	NeighborsDR uint32
	// The neighbor's idea of the Backup Designated Router.  If this is
	//        the neighbor itself, this is important in the local calculation
	//        of the Backup Designated Router.  Defined only on broadcast and
	//        NBMA networks.
	NeighborsBDR uint32

	//    The next set of variables are lists of LSAs.  These lists describe
	//    subsets of the area link-state database.  This memo defines five
	//    distinct types of LSAs, all of which may be present in an area
	//    link-state database: router-LSAs, network-LSAs, and Type 3 and 4
	//    summary-LSAs (all stored in the area data structure), and AS-
	//    external-LSAs (stored in the global data structure).

	// The list of LSAs that have been flooded but not acknowledged on
	//        this adjacency.  These will be retransmitted at intervals until
	//        they are acknowledged, or until the adjacency is destroyed.
	LSRetransmission []*packet.LSAdvertisement
	// The complete list of LSAs that make up the area link-state
	//        database, at the moment the neighbor goes into Database Exchange
	//        state.  This list is sent to the neighbor in Database
	//        Description packets.
	DatabaseSummary []*packet.LSAheader
	// The list of LSAs that need to be received from this neighbor in
	//        order to synchronize the two neighbors' link-state databases.
	//        This list is created as Database Description packets are
	//        received, and is then sent to the neighbor in Link State Request
	//        packets.  The list is depleted as appropriate Link State Update
	//        packets are received.
	LSRequest []*packet.LSReq
}

func (n *Neighbor) currState() NeighborState {
	return n.State
}

func (n *Neighbor) transState(target NeighborState) {
	n.State = target
}

func (n *Neighbor) shouldFormAdjacency() bool {
	return true
}

type NeighborStateChangingEvent int

const (
	_ NeighborStateChangingEvent = iota
	// NbEvHelloReceived An Hello packet has been received from the neighbor.
	NbEvHelloReceived
	// NbEvStart this is an indication that Hello Packets should now be sent
	//            to the neighbor at intervals of HelloInterval seconds.  This
	//            event is generated only for neighbors associated with NBMA
	//            networks.
	NbEvStart
	// NbEv2WayReceived Bidirectional communication has been realized between the
	//            two neighboring routers.  This is indicated by the router
	//            seeing itself in the neighbor's Hello packet.
	NbEv2WayReceived
	// NbEvNegotiationDone The Master/Slave relationship has been negotiated, and DD
	//            sequence numbers have been exchanged.  This signals the
	//            start of the sending/receiving of Database Description
	//            packets.  For more information on the generation of this
	//            event, consult Section 10.8.
	NbEvNegotiationDone
	// NbEvExchangeDone Both routers have successfully transmitted a full sequence
	//            of Database Description packets.  Each router now knows what
	//            parts of its link state database are out of date.  For more
	//            information on the generation of this event, consult Section
	//            10.8.
	NbEvExchangeDone
	// NbEvBadLSReq A Link State Request has been received for an LSA not
	//            contained in the database.  This indicates an error in the
	//            Database Exchange process.
	NbEvBadLSReq
	// NbEvLoadingDone Link State Updates have been received for all out-of-date
	//            portions of the database.  This is indicated by the Link
	//            state request list becoming empty after the Database
	//            Exchange process has completed.
	NbEvLoadingDone
	// NbEvIsAdjOK A decision must be made as to whether an adjacency should be
	//            established/maintained with the neighbor.  This event will
	//            start some adjacencies forming, and destroy others.
	NbEvIsAdjOK

	//        The following events cause well developed neighbors to revert to
	//        lesser states.  Unlike the above events, these events may occur
	//        when the neighbor conversation is in any of a number of states.

	// NbEvSeqNumberMismatch A Database Description packet has been received that either
	//            a) has an unexpected DD sequence number, b) unexpectedly has
	//            the Init bit set or c) has an Options field differing from
	//            the last Options field received in a Database Description
	//            packet.  Any of these conditions indicate that some error
	//            has occurred during adjacency establishment.
	NbEvSeqNumberMismatch
	// NbEv1Way An Hello packet has been received from the neighbor, in
	//            which the router is not mentioned.  This indicates that
	//            communication with the neighbor is not bidirectional.
	NbEv1Way
	// NbEvKillNbr This  is  an  indication that  all  communication  with  the
	//            neighbor  is now  impossible,  forcing  the  neighbor  to
	//            revert  to  Down  state.
	NbEvKillNbr
	// NbEvInactivityTimer The inactivity Timer has fired.  This means that no Hello
	//            packets have been seen recently from the neighbor.  The
	//            neighbor reverts to Down state.
	NbEvInactivityTimer
	// NbEvLLDown This is an indication from the lower level protocols that
	//            the neighbor is now unreachable.  For example, on an X.25
	//            network this could be indicated by an X.25 clear indication
	//            with appropriate cause and diagnostic fields.  This event
	//            forces the neighbor into Down state.
	NbEvLLDown
)

func (n *Neighbor) consumeEvent(e NeighborStateChangingEvent) {
	switch e {
	case NbEvStart: // NBMA networks only
		if n.currState() == NeighborDown {
			n.transState(NeighborAttempt)
			// Send an Hello Packet to the neighbor (this neighbor
			//                    is always associated with an NBMA network) and start
			//                    the Inactivity Timer for the neighbor.  The timer's
			//                    later firing would indicate that communication with
			//                    the neighbor was not attained.
		}
	case NbEvHelloReceived:
		if n.currState() == NeighborAttempt {
			// NBMA networks only
			n.transState(NeighborInit)
			n.startInactivityTimer()
		} else if n.currState() == NeighborDown {
			n.transState(NeighborInit)
			n.startInactivityTimer()
		} else if n.currState() >= NeighborInit {
			n.startInactivityTimer()
		}
	case NbEv2WayReceived:
		if n.currState() == NeighborInit {
			// Determine whether an adjacency should be established with the neighbor (see Section 10.4).
			// If not, the new neighbor state is 2-Way.
			// Otherwise (an adjacency should be established) the neighbor state transitions to ExStart.
			if n.shouldFormAdjacency() {
				n.transState(NeighborExStart)
				n.startMasterNegotiation()
			} else {
				n.transState(Neighbor2Way)
			}
		}
	case NbEvNegotiationDone:
		if n.currState() == NeighborExStart {
			n.transState(NeighborExchange)
			n.startExchange()
		}
	case NbEvExchangeDone:
		if n.currState() == NeighborExchange {
			// If the neighbor Link state request list is empty,
			//                    the new neighbor state is Full.  No other action is
			//                    required.  This is an adjacency's final state.
			//
			//                    Otherwise, the new neighbor state is Loading.  Start
			//                    (or continue) sending Link State Request packets to
			//                    the neighbor (see Section 10.9).  These are requests
			//                    for the neighbor's more recent LSAs (which were
			//                    discovered but not yet received in the Exchange
			//                    state).  These LSAs are listed in the Link state
			//                    request list associated with the neighbor.
		}
	case NbEvLoadingDone:
		if n.currState() == NeighborLoading {
			n.transState(NeighborFull)
		}
	case NbEvIsAdjOK:
		if n.currState() == Neighbor2Way {
			// Determine whether an adjacency should be formed with
			//                    the neighboring router (see Section 10.4).  If not,
			//                    the neighbor state remains at 2-Way.  Otherwise,
			//                    transition the neighbor state to ExStart and perform
			//                    the actions associated with the above state machine
			//                    entry for state Init and event 2-WayReceived.
		} else if n.currState() >= NeighborExStart {
			// Determine whether the neighboring router should
			//                    still be adjacent.  If yes, there is no state change
			//                    and no further action is necessary.
			//
			//                    Otherwise, the (possibly partially formed) adjacency
			//                    must be destroyed.  The neighbor state transitions
			//                    to 2-Way.  The Link state retransmission list,
			//                    Database summary list and Link state request list
			//                    are cleared of LSAs.
		}
	case NbEvSeqNumberMismatch:
		if n.currState() >= NeighborExchange {
			n.transState(NeighborExStart)
			// The (possibly partially formed) adjacency is torn
			//                    down, and then an attempt is made at
			//                    reestablishment.  The neighbor state first
			//                    transitions to ExStart.  The Link state
			//                    retransmission list, Database summary list and Link
			//                    state request list are cleared of LSAs.  Then the
			//                    router increments the DD sequence number in the
			//                    neighbor data structure, declares itself master
			//                    (sets the master/slave bit to master), and starts
			//                    sending Database Description Packets, with the
			//                    initialize (I), more (M) and master (MS) bits set.
			//                    This Database Description Packet should be otherwise
			//                    empty (see Section 10.8).
		}
	case NbEvBadLSReq:
		if n.currState() >= NeighborExchange {
			n.transState(NeighborExStart)
			// The action for event BadLSReq is exactly the same as
			//                    for the neighbor event SeqNumberMismatch.  The
			//                    (possibly partially formed) adjacency is torn down,
			//                    and then an attempt is made at reestablishment.  For
			//                    more information, see the neighbor state machine
			//                    entry that is invoked when event SeqNumberMismatch
			//                    is generated in state Exchange or greater.
		}
	case NbEvKillNbr:
		n.transState(NeighborDown)
		// The Link state retransmission list, Database summary
		//                    list and Link state request list are cleared of
		//                    LSAs.  Also, the Inactivity Timer is disabled.
	case NbEvLLDown:
		n.transState(NeighborDown)
		// The Link state retransmission list, Database summary
		//                    list and Link state request list are cleared of
		//                    LSAs.  Also, the Inactivity Timer is disabled.
	case NbEvInactivityTimer:
		n.transState(NeighborDown)
		// The Link state retransmission list, Database summary
		//                    list and Link state request list are cleared of
		//                    LSAs.
	case NbEv1Way:
		if n.currState() >= Neighbor2Way {
			n.transState(NeighborInit)
			// The Link state retransmission list, Database summary
			//                    list and Link state request list are cleared of
			//                    LSAs.
		}
	}
}

func (n *Neighbor) startInactivityTimer() {
	inactiveDur := time.Duration(n.i.RouterDeadInterval) * time.Second
	if n.InactivityTimer == nil {
		n.InactivityTimer = time.AfterFunc(inactiveDur,
			func() {
				n.consumeEvent(NbEvInactivityTimer)
				n.i.removeNeighbor(n)
			})
	} else {
		n.InactivityTimer.Reset(inactiveDur)
	}
}

func (n *Neighbor) startMasterNegotiation() {
	n.DDSeqNumber = randSource.Uint32N(math.MaxUint32 / 2)
	dd := &packet.OSPFv2Packet[packet.DbDescPayload]{
		OSPFv2: layers.OSPFv2{
			OSPF: layers.OSPF{
				Version:  2,
				Type:     layers.OSPFDatabaseDescription,
				RouterID: n.i.Area.ins.RouterId,
				AreaID:   n.i.Area.AreaId,
			},
		},
		Content: packet.DbDescPayload{
			DbDescPkg: layers.DbDescPkg{
				Options:      uint32(n.i.Area.Options),
				InterfaceMTU: 1500,
				Flags: uint16(packet.BitOption(0).SetBit(packet.DDOptionMSbit,
					packet.DDOptionIbit, packet.DDOptionMbit)),
				DDSeqNumber: n.DDSeqNumber,
			},
		},
	}
	// TODO: retransmitted at intervals of RxmtInterval until the next state is entered
	n.i.queuePktForSend(sendPkt{
		dst: allSPFRouters,
		p:   dd,
	})
}

func (n *Neighbor) startExchange() {

}
