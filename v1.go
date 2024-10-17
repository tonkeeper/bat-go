package bat

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

type TokenV1 struct {
	AppID      uint32
	TokenID    uint32
	IsSubtoken bool
	SubtokenID uint32
	ExpireAt   *time.Time
	Limits     *RateLimits
	ipVersion  byte
	ipHash     uint32
	Signature  [32]byte
	Webhooks   bool
}

func NewTokenV1(appID, tokenID uint32) *TokenV1 {
	return &TokenV1{AppID: appID, TokenID: tokenID}
}

func (t *TokenV1) WithSubtokenID(id uint32) *TokenV1 {
	t.IsSubtoken = true
	t.SubtokenID = id
	return t
}

func (t *TokenV1) WithWebhooks() *TokenV1 {
	t.Webhooks = true
	return t
}

func (t *TokenV1) WithTTL(duration time.Duration) *TokenV1 {
	t1 := time.Now().Add(duration)
	t.ExpireAt = &t1
	return t
}

func (t *TokenV1) WithExpireAt(t1 time.Time) *TokenV1 {
	t.ExpireAt = &t1
	return t
}

func (t *TokenV1) WithRateLimits(rps float32, burstMultiplicator uint8, perIP bool) *TokenV1 {
	t.Limits = &RateLimits{RPS: rps, BurstMultiplicator: burstMultiplicator, PerIP: perIP}
	return t
}

func (t TokenV1) String() string {
	return strings.TrimRight(base32.StdEncoding.EncodeToString(append(t.serialize(), t.Signature[:]...)), "=")
}

func (t TokenV1) serialize() []byte {
	b := make([]byte, 10, 64)
	b[0] = Version1
	binary.BigEndian.PutUint32(b[1:5], t.AppID)
	binary.BigEndian.PutUint32(b[5:9], t.TokenID)
	if t.IsSubtoken {
		b[9] = 1
		b = binary.BigEndian.AppendUint32(b, t.SubtokenID)
	}
	var flags uint16
	flagsOffset := len(b)
	b = append(b, 0, 0)
	if t.ExpireAt != nil {
		flags = setBit(flags, 0)
		b = binary.BigEndian.AppendUint32(b, uint32(t.ExpireAt.Unix()))
	}
	if t.Limits != nil {
		flags = setBit(flags, 1)
		b = append(b, encodeLimits(*t.Limits)...)
	}
	if t.ipVersion != 0 {
		flags = setBit(flags, 2)
		b = append(b, t.ipVersion)
		b = binary.BigEndian.AppendUint32(b, t.ipHash)
	}
	if t.Webhooks {
		flags = setBit(flags, 3)
	}
	binary.BigEndian.PutUint16(b[flagsOffset:flagsOffset+2], flags)
	return b
}

func (t *TokenV1) Sign(secret []byte) []byte {
	h := hmac.New(sha256.New, secret)
	h.Write(t.serialize())
	return h.Sum(t.Signature[:0])
}

func (t *TokenV1) parse(b []byte) error {
	if len(b) < 9 {
		return fmt.Errorf("invalid token length %v", len(b))
	}
	t.AppID = binary.BigEndian.Uint32(b[:4])
	t.TokenID = binary.BigEndian.Uint32(b[4:8])
	t.IsSubtoken = b[8] == 1
	offset := 9
	if t.IsSubtoken {
		if len(b) < offset+4 {
			return fmt.Errorf("invalid token length %v", len(b))
		}
		t.SubtokenID = binary.BigEndian.Uint32(b[offset : offset+4])
		offset += 4
	}
	if len(b) < offset+2 {
		return fmt.Errorf("invalid token length %v", len(b))
	}
	flags := binary.BigEndian.Uint16(b[offset : offset+2])
	offset += 2
	if isBitSet(flags, 0) {
		if len(b) < offset+4 {
			return fmt.Errorf("invalid token length %v", len(b))
		}
		expire := time.Unix(int64(binary.BigEndian.Uint32(b[offset:offset+4])), 0)
		offset += 4
		t.ExpireAt = &expire
	}
	if isBitSet(flags, 1) {
		if len(b) < offset+6 {
			return fmt.Errorf("invalid token length %v", len(b))
		}
		t.Limits = parsLimit(b[offset : offset+6])
		offset += 6
	}
	if isBitSet(flags, 2) {
		if len(b) < offset+5 {
			return fmt.Errorf("invalid token length %v", len(b))
		}
		t.ipVersion = b[offset]
		offset++
		t.ipHash = binary.BigEndian.Uint32(b[offset : offset+4])
		offset += 4
	}
	if isBitSet(flags, 3) {
		t.Webhooks = true
	}
	if len(b) < offset+32 {
		return fmt.Errorf("invalid token length %v", len(b))
	}
	copy(t.Signature[:], b[offset:offset+32])
	return nil
}

func (t *TokenV1) ValidSignature(secret []byte) bool {
	h := hmac.New(sha256.New, secret)
	h.Write(t.serialize())
	return hmac.Equal(t.Signature[:], h.Sum(nil))
}

func setBit(u uint16, b int) uint16 {
	if b > 15 {
		return u
	}
	mask := uint16(1) << (15 - b)
	return u | mask
}

func isBitSet(u uint16, b int) bool {
	if b > 15 {
		return false
	}
	mask := uint16(1) << (15 - b)
	return u&mask == mask
}
