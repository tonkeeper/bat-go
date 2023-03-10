package bat_go

import (
	"testing"
	"time"
)

func TestBasic(t *testing.T) {
	token := NewTokenV1(10, 20).WithSubtokenID(34534).WithTTL(time.Hour)
	token.Sign([]byte("secret"))
	s := token.String1()
	token2, err := ParseToken(s)
	if err != nil {
		t.Fatal(err)
	}
	if token.TokenID != token2.TokenID {
		t.Fatal(token2.TokenID)
	}
	if token.AppID != token2.AppID {
		t.Fatal(token2.AppID)
	}
	if token.SubtokenID != token2.SubtokenID {
		t.Fatal(token2.SubtokenID)
	}
	if token.ExpireAt.Unix() != token2.ExpireAt.Unix() {
		t.Fatal(token2.ExpireAt.Unix())
	}
	if !token2.ValidSignature([]byte("secret")) {
		t.Fatal("invalid signature")
	}
}
