package ospf

import (
	"context"
	"encoding/binary"
	"sync/atomic"
	"time"
	"unsafe"
)

func ipv4BytesToUint32(b []byte) uint32 {
	return binary.BigEndian.Uint32(b[0:4])
}

func ipv4MaskToUint32(b []byte) uint32 {
	return binary.BigEndian.Uint32(b[0:4])
}

type TickerFunc struct {
	ctx    context.Context
	cancel context.CancelFunc
	t      *time.Ticker
}

func TimeTickerFunc(ctx context.Context, dur time.Duration, fn func()) *TickerFunc {
	ctx, cancel := context.WithCancel(ctx)
	ret := &TickerFunc{
		ctx:    ctx,
		cancel: cancel,
		t:      time.NewTicker(dur),
	}
	go func() {
		// immediate call the fn first
		fn()
		// then loop for cancel or tick
		for {
			select {
			case <-ret.ctx.Done():
				ret.t.Stop()
				return
			case <-ret.t.C:
				fn()
			}
		}
	}()
	return ret
}

func (t *TickerFunc) Stop() {
	if t != nil {
		t.cancel()
	}
}

// TSS for thread-safe struct
type TSS[T any] struct {
	v unsafe.Pointer
}

func (s *TSS[T]) Set(val T) {
	atomic.StorePointer(&s.v, unsafe.Pointer(&val))
}

func (s *TSS[T]) Get() (ret T) {
	vGet := (*T)(atomic.LoadPointer(&s.v))
	if vGet == nil {
		return
	}
	return *vGet
}
