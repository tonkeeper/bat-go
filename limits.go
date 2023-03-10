package bat

import (
	"encoding/binary"
	"math"
)

type RateLimits struct {
	RPS                float32
	BurstMultiplicator uint8
	PerIP              bool
}

func encodeLimits(l RateLimits) []byte {
	b := make([]byte, 6)
	binary.BigEndian.PutUint32(b[:4], math.Float32bits(l.RPS))
	b[4] = l.BurstMultiplicator
	if l.PerIP {
		b[5] = 1
	}
	return b
}

func parsLimit(b []byte) *RateLimits {
	rps := math.Float32frombits(binary.BigEndian.Uint32(b[:4]))
	return &RateLimits{RPS: rps, BurstMultiplicator: b[4], PerIP: b[5] == 1}
}
