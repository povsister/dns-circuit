package packet

import (
	"testing"

	"github.com/google/gopacket/layers"
)

func TestLSAChkSum(t *testing.T) {
	lsa := LSAdvertisement{
		LSAheader: LSAheader{
			LSType:      layers.RouterLSAtypeV2,
			LinkStateID: 11223344,
			AdvRouter:   11223344,
			LSSeqNumber: InitialSequenceNumber,
			LSOptions:   uint8(BitOption(0).SetBit(CapabilityEbit)),
		},
		Content: V2RouterLSA{
			RouterLSAV2: layers.RouterLSAV2{
				Flags: 0,
				Links: 1,
			},
			Routers: []RouterV2{
				{
					RouterV2: layers.RouterV2{
						Type:     2,
						LinkID:   11223344,
						LinkData: 11223344,
						Metric:   20,
					},
				},
			},
		},
	}
	buf := make([]byte, lsa.Size())
	err := lsa.SerializeToSizedBuffer(buf)
	if err != nil {
		t.Fatalf("failed to serialize lsa: %s", err)
	}
	t.Logf("%+v", lsa)

}
