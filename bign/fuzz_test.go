package bign

import (
	"bytes"
	"testing"
)

func FuzzParamsDER(f *testing.F) {
	for _, oid := range []string{Curve256v1, Curve384v1, Curve512v1} {
		p, e := StandardParams(oid)
		if e != nil {
			f.Fatal(e)
		}
		der, e := p.DER()
		p.Close()
		if e != nil {
			f.Fatal(e)
		}
		f.Add(der)
		f.Add(der[:len(der)-1])
	}
	f.Add([]byte{0x30, 0x80, 0, 0})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, der []byte) {
		if len(der) > 2048 {
			return
		}
		p, e := ParamsFromDER(der)
		if e != nil {
			return
		}
		defer p.Close()
		if e = p.Validate(); e != nil {
			t.Fatalf("accepted invalid parameters: %v", e)
		}
		encoded, e := p.DER()
		if e != nil {
			t.Fatal(e)
		}
		q, e := ParamsFromDER(encoded)
		if e != nil {
			t.Fatal(e)
		}
		defer q.Close()
		again, e := q.DER()
		if e != nil || !bytes.Equal(encoded, again) {
			t.Fatalf("unstable DER: %v", e)
		}
	})
}
