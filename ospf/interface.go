package ospf

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/google/gopacket"
	"golang.org/x/net/ipv4"

	"github.com/povsister/dns-circuit/ospf/packet"
)

type InterfaceConfig struct {
	IfName             string
	Address            *net.IPNet
	RouterPriority     uint8
	HelloInterval      uint16
	RouterDeadInterval uint32
}

func NewInterface(ctx context.Context, c *InterfaceConfig) *Interface {
	ifi, err := net.InterfaceByName(c.IfName)
	if err != nil {
		panic(fmt.Errorf("can not find InterfaceByName: %w", err))
	}
	conn, err := ListenOSPFv2Multicast(ctx, ifi, "0.0.0.0", c.Address.IP.String())
	if err != nil {
		panic(fmt.Errorf("can not bind OSPFv2 multicast conn: %w", err))
	}
	ctx, cancel := context.WithCancel(ctx)
	return &Interface{
		ctx:                ctx,
		cancel:             cancel,
		c:                  conn,
		wg:                 &sync.WaitGroup{},
		pendingProcessPkt:  make(chan recvPkt, 20),
		pendingSendPkt:     make(chan sendPkt, 20),
		Address:            c.Address,
		RouterPriority:     c.RouterPriority,
		HelloInterval:      c.HelloInterval,
		RouterDeadInterval: c.RouterDeadInterval,
		Neighbors:          make(map[uint32]*Neighbor),
		OutputCost:         10,
		RxmtInterval:       5,
		InfTransDelay:      1,
		nbMu:               &sync.RWMutex{},
	}
}

type recvPkt struct {
	h *ipv4.Header
	p []byte
}

type sendPkt struct {
	dst uint32
	p   gopacket.SerializableLayer // ospf msg
}

type InterfaceState uint8

const (
	// InterfaceDown This is the initial interface state.  In this state, the
	//            lower-level protocols have indicated that the interface is
	//            unusable.  No protocol traffic at all will be sent or
	//            received on such a interface.  In this state, interface
	//            parameters should be set to their initial values.  All
	//            interface timers should be disabled, and there should be no
	//            adjacencies associated with the interface.
	InterfaceDown InterfaceState = iota
	// InterfaceLoopBack In this state, the router's interface to the network is
	//            looped back.  The interface may be looped back in hardware
	//            or software.  The interface will be unavailable for regular
	//            data traffic.  However, it may still be desirable to gain
	//            information on the quality of this interface, either through
	//            sending ICMP pings to the interface or through something
	//            like a bit error test.  For this reason, IP packets may
	//            still be addressed to an interface in Loopback state.  To
	//            facilitate this, such interfaces are advertised in router-
	//            LSAs as single host routes, whose destination is the IP
	//            interface address.[4]
	InterfaceLoopBack
	// InterfaceWaiting In this state, the router is trying to determine the
	//            identity of the (Backup) Designated Router for the network.
	//            To do this, the router monitors the Hello Packets it
	//            receives.  The router is not allowed to elect a Backup
	//            Designated Router nor a Designated Router until it
	//            transitions out of Waiting state.  This prevents unnecessary
	//            changes of (Backup) Designated Router.
	InterfaceWaiting
	// InterfacePointToPoint In this state, the interface is operational, and connects
	//            either to a physical point-to-point network or to a virtual
	//            link.  Upon entering this state, the router attempts to form
	//            an adjacency with the neighboring router.  Hello Packets are
	//            sent to the neighbor every HelloInterval seconds.
	InterfacePointToPoint
	// InterfaceDROther The interface is to a broadcast or NBMA network on which
	//            another router has been selected to be the Designated
	//            Router.  In this state, the router itself has not been
	//            selected Backup Designated Router either.  The router forms
	//            adjacencies to both the Designated Router and the Backup
	//            Designated Router (if they exist).
	InterfaceDROther
	// InterfaceBackup In this state, the router itself is the Backup Designated
	//            Router on the attached network.  It will be promoted to
	//            Designated Router when the present Designated Router fails.
	//            The router establishes adjacencies to all other routers
	//            attached to the network.  The Backup Designated Router
	//            performs slightly different functions during the Flooding
	//            Procedure, as compared to the Designated Router (see Section
	//            13.3).  See Section 7.4 for more details on the functions
	//            performed by the Backup Designated Router.
	InterfaceBackup
	// InterfaceDR In this state, this router itself is the Designated Router
	//            on the attached network.  Adjacencies are established to all
	//            other routers attached to the network.  The router must also
	//            originate a network-LSA for the network node.  The network-
	//            LSA will contain links to all routers (including the
	//            Designated Router itself) attached to the network.  See
	//            Section 7.3 for more details on the functions performed by
	//            the Designated Router.
	InterfaceDR
)

type Interface struct {
	// internal use

	c      *Conn
	ctx    context.Context
	cancel context.CancelFunc
	wg     *sync.WaitGroup

	pendingProcessPkt chan recvPkt
	pendingSendPkt    chan sendPkt

	// The OSPF interface type is either point-to-point, broadcast,
	//        NBMA, Point-to-MultiPoint or virtual link.
	// Not used yet.
	Type string
	// The functional level of an interface.  State determines whether
	//        or not full adjacencies are allowed to form over the interface.
	//        State is also reflected in the router's LSAs.
	State InterfaceState
	// The IP address associated with the interface.  This appears as
	//        the IP source address in all routing protocol packets originated
	//        over this interface.  Interfaces to unnumbered point-to-point
	//        networks do not have an associated IP address.
	// Also referred to as the subnet mask, this indicates the portion
	//        of the IP interface address that identifies the attached
	//        network.  Masking the IP interface address with the IP interface
	//        mask yields the IP network number of the attached network.  On
	//        point-to-point networks and virtual links, the IP interface mask
	//        is not defined. On these networks, the link itself is not
	//        assigned an IP network number, and so the addresses of each side
	//        of the link are assigned independently, if they are assigned at
	//        all.
	Address *net.IPNet
	// The Area ID of the area to which the attached network belongs.
	//        All routing protocol packets originating from the interface are
	//        labelled with this Area ID.
	Area *Area

	// An 8-bit unsigned integer.  When two routers attached to a
	//        network both attempt to become Designated Router, the one with
	//        the highest Router Priority takes precedence.  A router whose
	//        Router Priority is set to 0 is ineligible to become Designated
	//        Router on the attached network.  Advertised in Hello packets
	//        sent out this interface.
	RouterPriority uint8

	// The length of time, in seconds, between the Hello packets that
	//        the router sends on the interface.  Advertised in Hello packets
	//        sent out this interface.
	HelloInterval uint16
	// An interval timer that causes the interface to send a Hello
	//        packet.  This timer fires every HelloInterval seconds.  Note
	//        that on non-broadcast networks a separate Hello packet is sent
	//        to each qualified neighbor.
	HelloTicker *time.Ticker
	// The number of seconds before the router's neighbors will declare
	//        it down, when they stop hearing the router's Hello Packets.
	//        Advertised in Hello packets sent out this interface.
	RouterDeadInterval uint32
	// A single shot timer that causes the interface to exit the
	//        Waiting state, and as a consequence select a Designated Router
	//        on the network.  The length of the timer is RouterDeadInterval
	//        seconds.
	WaitTimer *time.Timer
	// The Designated Router selected for the attached network.  The
	//        Designated Router is selected on all broadcast and NBMA networks
	//        by the Hello Protocol.  Two pieces of identification are kept
	//        for the Designated Router: its Router ID and its IP interface
	//        address on the network.  The Designated Router advertises link
	//        state for the network; this network-LSA is labelled with the
	//        Designated Router's IP address.  The Designated Router is
	//        initialized to 0.0.0.0, which indicates the lack of a Designated
	//        Router.
	DR uint32
	// The Backup Designated Router is also selected on all broadcast
	//        and NBMA networks by the Hello Protocol.  All routers on the
	//        attached network become adjacent to both the Designated Router
	//        and the Backup Designated Router.  The Backup Designated Router
	//        becomes Designated Router when the current Designated Router
	//        fails.  The Backup Designated Router is initialized to 0.0.0.0,
	//        indicating the lack of a Backup Designated Router.
	BDR uint32

	nbMu *sync.RWMutex
	// The other routers attached to this network.  This list is formed
	//        by the Hello Protocol.  Adjacencies will be formed to some of
	//        these neighbors.  The set of adjacent neighbors can be
	//        determined by an examination of all of the neighbors' states.
	Neighbors map[uint32]*Neighbor

	// The cost of sending a packet on the interface, expressed in
	//            the link state metric.  This is advertised as the link cost
	//            for this interface in the router's router-LSA. The interface
	//            output cost must always be greater than 0.
	OutputCost int

	// The number of seconds between LSA retransmissions, for
	//            adjacencies belonging to this interface.  Also used when
	//            retransmitting Database Description and Link State Request
	//            Packets.  This should be well over the expected round-trip
	//            delay between any two routers on the attached network.  The
	//            setting of this value should be conservative or needless
	//            retransmissions will result.  Sample value for a local area
	//            network: 5 seconds.
	RxmtInterval int

	// The estimated number of seconds it takes to transmit a Link
	//            State Update Packet over this interface.  LSAs contained in
	//            the update packet must have their age incremented by this
	//            amount before transmission.  This value should take into
	//            account the transmission and propagation delays of the
	//            interface.  It must be greater than 0.  Sample value for a
	//            local area network: 1 second.
	InfTransDelay int

	// TODO
	AuType string
	// TODO
	Authentication string
}

func (i *Interface) start() {
	i.runReadLoop()
	i.runSendLoop()
	i.runReadDispatchLoop()
	i.runHelloTicker()
}

func (i *Interface) close() error {
	i.cancel()
	i.wg.Wait()
	return i.c.Close()
}

func (i *Interface) runReadDispatchLoop() {
	i.wg.Add(1)
	go func() {
		for {
			select {
			case <-i.ctx.Done():
				i.wg.Done()
				return
			case pkt := <-i.pendingProcessPkt:
				i.doReadDispatch(pkt)
			}
		}
	}()
}

func (i *Interface) runReadLoop() {
	i.wg.Add(1)
	go func() {
		const recvBufLen = 64 << 10
		var (
			buf = make([]byte, recvBufLen)
			n   int
			h   *ipv4.Header
			err error
		)
		for {
			select {
			case <-i.ctx.Done():
				i.wg.Done()
				return
			default:
				n, h, err = i.c.Read(buf)
				if err != nil {
					if !errors.Is(err, os.ErrDeadlineExceeded) {
						logWarn("Interface %s read err: %v", i.c.ifi.Name, err)
					}
					continue
				}
				if h.Flags&ipv4.MoreFragments == 1 || h.FragOff != 0 {
					// TODO: deal with ipv4 fragment
					logErr("Interface %s received fragmented IPv4 packet %s->%s and discarded",
						i.c.ifi.Name, h.Src.String(), h.Dst.String())
					continue
				}
				payloadLen := n - ipv4.HeaderLen
				if h != nil {
					logDebug("Interface %s received %s->%s payloadSize(%d)", i.c.ifi.Name, h.Src.String(), h.Dst.String(), payloadLen)
				}
				payload := make([]byte, payloadLen)
				copy(payload, buf[ipv4.HeaderLen:n])
				select {
				case i.pendingProcessPkt <- recvPkt{h: h, p: payload}:
				default:
					logWarn("Interface %s pendingProcPkt full. Discarding 1 pkt(%d)", i.c.ifi.Name, payloadLen)
				}
			}
		}
	}()
}

func (i *Interface) runSendLoop() {
	i.wg.Add(1)
	go func() {
		var err error
		for {
			select {
			case <-i.ctx.Done():
				i.wg.Done()
				return
			case pkt := <-i.pendingSendPkt:
				if err = i.doSendPkt(pkt); err != nil {
					// TODO: ?
				}
			}
		}
	}()
}

func (i *Interface) doSendPkt(pkt sendPkt) (err error) {
	p := gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(p, gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}, pkt.p)
	if err != nil {
		logErr("Interface %s err marshal pending send Packet: %v", i.c.ifi.Name, err)
		return nil
	}
	n, err := i.c.WriteTo(p.Bytes(), &net.IPAddr{
		IP: net.IPv4(byte(pkt.dst>>24), byte(pkt.dst>>16), byte(pkt.dst>>8), byte(pkt.dst)),
	})
	if err != nil {
		logErr("Interface %s err send Packet: %v", i.c.ifi.Name, err)
	} else {
		logDebug("Interface %s sent Packets(%d): \n%+v", i.c.ifi.Name, n, pkt.p)
	}
	return
}

func (i *Interface) runHelloTicker() {
	i.HelloTicker = time.NewTicker(time.Duration(i.HelloInterval) * time.Second)
	i.wg.Add(1)
	go func() {
		var err error
		select {
		case <-i.ctx.Done():
			i.HelloTicker.Stop()
			i.wg.Done()
			return
		case <-i.HelloTicker.C:
			// directly writes the pkt and doNot enter queue.
			if err = i.doHello(); err != nil {
				// TODO: more aggressive retry ?
			}
		}
	}()
}

func (i *Interface) getNeighbor(rtId uint32) (nb *Neighbor, ok bool) {
	i.nbMu.RLock()
	defer i.nbMu.RUnlock()
	nb, ok = i.Neighbors[rtId]
	return
}

func (i *Interface) removeNeighbor(nb *Neighbor) {
	i.nbMu.Lock()
	defer i.nbMu.Unlock()
	delete(i.Neighbors, nb.NeighborId)
}

func (i *Interface) addNeighbor(h *ipv4.Header, hello *packet.OSPFv2Packet[packet.HelloPayloadV2]) *Neighbor {
	nb := &Neighbor{
		lastSeen:         time.Now(),
		i:                i,
		State:            NeighborDown,
		IsMaster:         hello.RouterID > i.Area.ins.RouterId,
		NeighborId:       hello.RouterID,
		NeighborPriority: hello.Content.RtrPriority,
		NeighborAddress:  h.Src,
		NeighborOptions:  packet.BitOption(hello.Content.Options),
		NeighborsDR:      hello.Content.DesignatedRouterID,
		NeighborsBDR:     hello.Content.BackupDesignatedRouterID,
	}
	i.nbMu.Lock()
	defer i.nbMu.Unlock()
	i.Neighbors[hello.RouterID] = nb
	return nb
}
