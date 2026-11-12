package belt

import (
	"bytes"
	"errors"
	bee2 "github.com/miniusercoder/bee2go/v3"
	"testing"
)

func TestTruncatedVerification(t *testing.T) {
	h := beltHBytes()
	sum, e := Hash(h[:13])
	if e != nil {
		t.Fatal(e)
	}
	short, e := HashN(h[:13], 12)
	if e != nil || !bytes.Equal(short, sum[:12]) {
		t.Fatal(e)
	}
	ok, e := HashVerify(h[:13], short)
	if e != nil || !ok {
		t.Fatal(e)
	}
	short[0] ^= 1
	ok, e = HashVerify(h[:13], short)
	if e != nil || ok {
		t.Fatal(e)
	}
	if _, e = HashN(nil, 33); !errors.Is(e, bee2.ErrInvalidInput) {
		t.Fatal(e)
	}
	for _, tc := range []struct {
		f      func([]byte, []byte, int) ([]byte, error)
		verify func([]byte, []byte, []byte) (bool, error)
		n      int
	}{{MACN, MACVerify, 8}, {HMACN, HMACVerify, 32}} {
		tag, e := tc.f(h[:48], h[128:160], tc.n-1)
		if e != nil {
			t.Fatal(e)
		}
		ok, e := tc.verify(h[:48], h[128:160], tag)
		if e != nil || !ok {
			t.Fatal(e)
		}
		tag[0] ^= 1
		ok, e = tc.verify(h[:48], h[128:160], tag)
		if e != nil || ok {
			t.Fatal(e)
		}
	}
}
