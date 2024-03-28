package ospf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"golang.org/x/net/context"
	"golang.org/x/net/ipv4"
)

type Router struct {
	ifName string
	ifi    *net.Interface

	c             *Conn
	recvQ         chan ospfMsg
	sendQ         chan ospfMsg
	sendMulticast chan []byte

	startOnce sync.Once
	ctx       context.Context
	cancel    context.CancelFunc

	hasCompletelyShutdown sync.WaitGroup
	closeErr              error
	closeOnce             sync.Once

	// ospf instance
	ins *Instance
}

func NewRouter(ifName string, addr string, rtid string) (*Router, error) {
	ifi, err := net.InterfaceByName(ifName)
	if err != nil {
		return nil, fmt.Errorf("ospf: %w", err)
	}
	conn, err := ListenOSPFv2Multicast(context.Background(), ifi, addr, rtid)
	if err != nil {
		return nil, fmt.Errorf("ospf: %w", err)
	}
	r := &Router{
		ifName:        ifName,
		ifi:           ifi,
		c:             conn,
		recvQ:         make(chan ospfMsg, 20),
		sendQ:         make(chan ospfMsg, 20),
		sendMulticast: make(chan []byte, 20),
		ins: &Instance{
			cfg: &InstanceConfig{
				RouterId:           binary.BigEndian.Uint32(net.ParseIP(rtid).To4()[0:4]),
				HelloInterval:      10,
				RouterDeadInterval: 40,
			},
			Area: &Area{
				Id:           0, // backbone
				AdjNeighbors: make(map[uint32]*KnownNeighbors),
			},
		},
	}
	return r, nil
}

func (r *Router) Start() {
	r.startOnce.Do(func() {
		r.ctx, r.cancel = context.WithCancel(context.Background())
		r.hasCompletelyShutdown.Add(1)
		go r.runRecvLoop()
		r.hasCompletelyShutdown.Add(1)
		go r.runProcessLoop()
		r.hasCompletelyShutdown.Add(1)
		go r.runMulticastSendLoop()
		r.runIntervalTasks()
	})
}

func (r *Router) StartEcho() {
	r.startOnce.Do(func() {
		r.ctx, r.cancel = context.WithCancel(context.Background())
		r.hasCompletelyShutdown.Add(1)
		go r.runEchoLoop()
	})
}

func (r *Router) runEchoLoop() {
	for {
		select {
		case <-r.ctx.Done():
			r.hasCompletelyShutdown.Done()
			return
		default:
			n, err := r.c.WriteMulticastAllSPF([]byte(fmt.Sprintf("Ping%d", time.Now().Unix())))
			fmt.Printf("Sent %d bytes err(%v)\n", n, err)
			time.Sleep(1 * time.Second)
		}
	}
}

func (r *Router) runMulticastSendLoop() {
	for {
		select {
		case <-r.ctx.Done():
			r.hasCompletelyShutdown.Done()
			return
		case payload := <-r.sendMulticast:
			n, err := r.c.WriteMulticastAllSPF(payload)
			if err != nil {
				fmt.Println("err write", len(payload), "bytes:", err)
			} else {
				fmt.Println("multicast wrote", n, "bytes")
			}
		}
	}
}

func (r *Router) runRecvLoop() {
	const recvBufLen = 64 << 10
	var (
		buf = make([]byte, recvBufLen)
		n   int
		h   *ipv4.Header
		err error
	)
	for {
		clear(buf)
		select {
		case <-r.ctx.Done():
			r.hasCompletelyShutdown.Done()
			return
		default:
			n, h, err = r.c.Read(buf)
			if err != nil {
				if !errors.Is(err, os.ErrDeadlineExceeded) {
					fmt.Printf("Read err: %v\n", err)
				}
				continue
			}
			payloadLen := n - ipv4.HeaderLen
			if h != nil {
				fmt.Printf("Received %s->%s payloadSize(%d)\n", h.Src.String(), h.Dst.String(), payloadLen)
			}
			payload := make([]byte, payloadLen)
			copy(payload, buf[ipv4.HeaderLen:n])
			select {
			case r.recvQ <- ospfMsg{
				h: h,
				p: payload,
			}:
				//fmt.Printf("Sent %d bytes for processing\n", payloadLen)
			default:
				fmt.Printf("Discarded %d bytes due to recvQ full\n", payloadLen)
			}
		}
	}
}

func (r *Router) cleanup() {
}

func (r *Router) Close() (err error) {
	r.closeOnce.Do(func() {
		if r.cancel != nil {
			r.cancel()
		}
		r.cleanup()
		r.hasCompletelyShutdown.Wait()
		r.closeErr = r.c.Close()
	})
	return r.closeErr
}
