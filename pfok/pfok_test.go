package pfok

import (
	"bytes"
	"testing"
)

func TestAgreement(t *testing.T) {
	p, s, e := Standard("test")
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Validate(); e != nil {
		t.Fatal(e)
	}
	if e = p.Validate(); e != nil {
		t.Fatal(e)
	}
	a, A, e := p.GenerateKey(nil)
	if e != nil {
		t.Fatal(e)
	}
	b, B, e := p.GenerateKey(nil)
	if e != nil {
		t.Fatal(e)
	}
	calculated, e := p.PublicKey(a)
	if e != nil || !bytes.Equal(A, calculated) {
		t.Fatal("public key", e)
	}
	x, e := p.DH(a, B)
	if e != nil {
		t.Fatal(e)
	}
	y, e := p.DH(b, A)
	if e != nil || !bytes.Equal(x, y) {
		t.Fatal("DH mismatch", e)
	}
	x, e = p.MTI(a, a, B, B)
	if e != nil {
		t.Fatal(e)
	}
	y, e = p.MTI(b, b, A, A)
	if e != nil || !bytes.Equal(x, y) {
		t.Fatal("MTI mismatch", e)
	}
	if _, e = p.DH(a, make([]byte, len(B))); e == nil {
		t.Fatal("invalid public key")
	}
	if _, e = p.DH(nil, B); e == nil {
		t.Fatal("invalid private key length")
	}
}

func TestStandardParameters(t *testing.T) {
	for _, name := range []string{"test", "1.2.112.0.2.0.1176.2.3.3.2", "1.2.112.0.2.0.1176.2.3.6.2", "1.2.112.0.2.0.1176.2.3.10.2"} {
		p, s, e := Standard(name)
		if e != nil {
			t.Fatal(name, e)
		}
		if e = s.Validate(); e != nil {
			t.Fatal(name, e)
		}
		if e = p.Validate(); e != nil {
			t.Fatal(name, e)
		}
	}
	s := Seed{L: 638}
	if e := s.Adjust(); e != nil {
		t.Fatal(e)
	}
	s.LI[5] = 0
	if e := s.Validate(); e == nil {
		t.Fatal("invalid seed")
	}
	if _, _, e := Standard("test\x00bad"); e == nil {
		t.Fatal("embedded NUL")
	}
}
