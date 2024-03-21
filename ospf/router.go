package ospf

import (
	"fmt"
	"net"
	"sync"
	"time"

	"golang.org/x/net/context"
)

type Router struct {
	ifName string
	ifi    *net.Interface

	c *Conn

	startOnce sync.Once
	ctx       context.Context
	cancel    context.CancelFunc

	done      chan struct{}
	closeErr  error
	closeOnce sync.Once
}

func NewRouter(ifName string, addr string) (*Router, error) {
	ifi, err := net.InterfaceByName(ifName)
	if err != nil {
		return nil, fmt.Errorf("ospf: %w", err)
	}
	conn, err := ListenOSPFv2Multicast(ifi, addr)
	if err != nil {
		return nil, fmt.Errorf("ospf: %w", err)
	}
	r := &Router{
		ifName: ifName,
		ifi:    ifi,
		c:      conn,
	}
	return r, nil
}

func (r *Router) Start() {
	r.startOnce.Do(func() {
		r.ctx, r.cancel = context.WithCancel(context.Background())
		go r.runLoop()
	})
}

func (r *Router) StartEcho() {
	r.startOnce.Do(func() {
		r.ctx, r.cancel = context.WithCancel(context.Background())
		go r.runEchoLoop()
	})
}

func (r *Router) runEchoLoop() {
	r.done = make(chan struct{})
	for {
		select {
		case <-r.ctx.Done():
			r.done <- struct{}{}
		default:
			n, err := r.c.Write([]byte(fmt.Sprintf("Ping%d", time.Now().Unix())))
			fmt.Printf("Sent %d bytes err(%v)\n", n, err)
			time.Sleep(1 * time.Second)
		}
	}
}

func (r *Router) runLoop() {
	r.done = make(chan struct{})
	var (
		buf = make([]byte, 1<<10)
		n   int
		err error
	)
	for {
		clear(buf)
		select {
		case <-r.ctx.Done():
			r.cleanup()
			return
		default:
			n, err = r.c.Read(buf)
			fmt.Printf("Read %d bytes err(%v): %s\n", n, err, string(buf[0:n]))
		}
	}
}

func (r *Router) cleanup() {
	r.done <- struct{}{}
}

func (r *Router) Close() (err error) {
	r.closeOnce.Do(func() {
		if r.cancel != nil {
			r.cancel()
		}
		<-r.done
		r.closeErr = r.c.Close()
	})
	return r.closeErr
}
