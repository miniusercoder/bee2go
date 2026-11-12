package btok

import (
	"bytes"
	"github.com/miniusercoder/bee2go/v3/bake"
	"github.com/miniusercoder/bee2go/v3/bign"
	"testing"
)

func FuzzBAuthMessages(f *testing.F) {
	p, e := bign.StandardParams(bign.Curve256v1)
	if e != nil {
		f.Fatal(e)
	}
	defer p.Close()
	a := make([]byte, 32)
	a[0] = 1
	pub, e := bign.PublicKey(p, a)
	if e != nil {
		f.Fatal(e)
	}
	v := func([]byte, []byte) ([]byte, error) { return pub, nil }
	cert := bake.Certificate{Data: pub, Validate: v}
	f.Add([]byte{})
	f.Add(make([]byte, 96))
	f.Fuzz(func(t *testing.T, message []byte) {
		if len(message) > 2048 {
			return
		}
		s, e := NewBAuthTerminal(p, bake.Settings{ConfirmA: true, ConfirmB: true, Entropy: bytes.NewReader(make([]byte, 64))}, a, cert)
		if e != nil {
			t.Fatal(e)
		}
		defer s.Close()
		s.Step3(message)
		if key, e := s.Key(); key != nil || e == nil {
			t.Fatal("early key")
		}
	})
}
