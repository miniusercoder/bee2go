package btok

import (
	"bytes"
	"errors"
	bee2 "github.com/miniusercoder/bee2go/v3"
	"github.com/miniusercoder/bee2go/v3/bake"
	"github.com/miniusercoder/bee2go/v3/bign"
	"testing"
)

func TestBAuthAllLevels(t *testing.T) {
	for _, oid := range []string{bign.Curve256v1, bign.Curve384v1, bign.Curve512v1} {
		for _, mutual := range []bool{false, true} {
			p, e := bign.StandardParams(oid)
			if e != nil {
				t.Fatal(e)
			}
			defer p.Close()
			a, A, e := bign.GenerateKey(p, nil)
			if e != nil {
				t.Fatal(e)
			}
			b, B, e := bign.GenerateKey(p, nil)
			if e != nil {
				t.Fatal(e)
			}
			val := func(der, cert []byte) ([]byte, error) {
				if string(cert) == "terminal" {
					return A, nil
				}
				if string(cert) == "token" {
					return B, nil
				}
				return nil, errors.New("untrusted")
			}
			s := bake.Settings{ConfirmA: true, ConfirmB: mutual}
			T, e := NewBAuthTerminal(p, s, a, bake.Certificate{Data: []byte("terminal"), Validate: val})
			if e != nil {
				t.Fatal(e)
			}
			defer T.Close()
			C, e := NewBAuthToken(p, s, b, bake.Certificate{Data: []byte("token"), Validate: val})
			if e != nil {
				t.Fatal(e)
			}
			defer C.Close()
			if k, e := C.Key(); k != nil || !errors.Is(e, bee2.ErrState) {
				t.Fatal(e)
			}
			m1, e := C.Step2(bake.Certificate{Data: []byte("terminal"), Validate: val})
			if e != nil {
				t.Fatal(e)
			}
			m2, e := T.Step3(m1)
			if e != nil {
				t.Fatal(e)
			}
			m3, e := C.Step4(m2)
			if e != nil {
				t.Fatalf("%s mutual=%v: %v", oid, mutual, e)
			}
			if mutual {
				if e = T.Step5(m3, val); e != nil {
					t.Fatal(e)
				}
			}
			x, e := T.Key()
			if e != nil {
				t.Fatal(e)
			}
			y, e := C.Key()
			if e != nil || !bytes.Equal(x, y) {
				t.Fatal("keys differ", oid, mutual, e)
			}
		}
	}
}
func TestBAuthBadMessage(t *testing.T) {
	p, _ := bign.StandardParams(bign.Curve256v1)
	defer p.Close()
	a, A, _ := bign.GenerateKey(p, nil)
	val := func([]byte, []byte) ([]byte, error) { return A, nil }
	s, e := NewBAuthTerminal(p, bake.Settings{ConfirmA: true}, a, bake.Certificate{Data: []byte("test"), Validate: val})
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if _, e = s.Step3([]byte{1}); e == nil {
		t.Fatal("bad message")
	}
	if k, e := s.Key(); e == nil || k != nil {
		t.Fatal("key after error")
	}
}
