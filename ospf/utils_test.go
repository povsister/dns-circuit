package ospf

import (
	"math"
	"reflect"
	"testing"

	"github.com/gopacket/gopacket/layers"

	"github.com/povsister/dns-circuit/ospf/packet"
)

func TestTCS(t *testing.T) {
	s := struct {
		P TSS[*packet.OSPFv2Packet[packet.DbDescPayload]]
	}{}
	val := packet.OSPFv2Packet[packet.DbDescPayload]{
		OSPFv2: layers.OSPFv2{
			OSPF: layers.OSPF{
				Version: 2,
			},
		},
		Content: packet.DbDescPayload{
			DbDescPkg: layers.DbDescPkg{
				Options:      2,
				InterfaceMTU: 100,
				Flags:        0,
				DDSeqNumber:  999,
			},
		},
	}
	s.P.Set(&val)
	if !reflect.DeepEqual(val, *s.P.Get()) {
		t.Errorf("unexpected mismatch")
	}
}

func TestRandSource(t *testing.T) {
	for i := 0; i < 100; i++ {
		t.Log(packet.RandSource.Uint32N(math.MaxUint32 / 4))
	}
}

func TestBB(t *testing.T) {
	t.Logf("%b", packet.InitialSequenceNumber)
	t.Logf("%b", packet.MaxSequenceNumber)
}
