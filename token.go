package bat

import (
	"encoding/base32"
	"errors"
	"strings"
)

type Version = uint8

const Version1 Version = 1

type Token struct {
	version Version
	TokenV1
}

func ParseToken(s string) (Token, error) {
	if len(s)%8 != 0 {
		s += strings.Repeat("=", 8-len(s)%8)
	}
	b, err := base32.StdEncoding.DecodeString(s)
	if err != nil {
		return Token{}, err
	}
	if len(b) < 1 {
		return Token{}, errors.New("invalid token length")
	}
	if b[0] != Version1 {
		return Token{}, errors.New("invalid token version")
	}
	var t Token
	t.version = Version1
	err = t.TokenV1.parse(b[1:])
	return t, err
}
