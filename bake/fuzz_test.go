package bake

import (
	"bytes"
	"github.com/miniusercoder/bee2go/v3/bign"
	"testing"
)

func FuzzHandshakeMessages(f *testing.F) {
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
	cert := Certificate{Data: pub, Validate: v}
	f.Add(byte(0), []byte{})
	f.Add(byte(1), make([]byte, 64))
	f.Add(byte(2), make([]byte, 16))
	f.Fuzz(func(t *testing.T, kind byte, message []byte) {
		if len(message) > 2048 {
			return
		}
		s := Settings{ConfirmA: true, ConfirmB: true, Entropy: bytes.NewReader(make([]byte, 64))}
		switch kind % 3 {
		case 0:
			x, e := NewBMQV(p, RoleA, s, a, cert)
			if e != nil {
				t.Fatal(e)
			}
			defer x.Close()
			x.Step3(message, cert)
			if key, e := x.Key(); key != nil || e == nil {
				t.Fatal("early key")
			}
		case 1:
			x, e := NewBSTS(p, RoleA, s, a, cert)
			if e != nil {
				t.Fatal(e)
			}
			defer x.Close()
			x.Step3(message)
			if key, e := x.Key(); key != nil || e == nil {
				t.Fatal("early key")
			}
		case 2:
			x, e := NewBPACE(p, RoleA, s, []byte("password"))
			if e != nil {
				t.Fatal(e)
			}
			defer x.Close()
			x.Step3(message)
			if key, e := x.Key(); key != nil || e == nil {
				t.Fatal("early key")
			}
		}
	})
}
