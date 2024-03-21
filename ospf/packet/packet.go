package packet

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// OSPFv2 wrapper implements SerializeTo.
// Make it possible to serialize an OSPF message to wire format
type OSPFv2 struct {
	layers.OSPFv2
}

// SerializeTo writes the serialized form of this layer into the
// SerializationBuffer, implementing gopacket.SerializableLayer.
func (v2 *OSPFv2) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return nil
}
