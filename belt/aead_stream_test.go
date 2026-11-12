package belt

import (
	"bytes"
	"errors"
	bee2 "github.com/miniusercoder/bee2go/v3"
	"testing"
)

func TestAuthenticatedStream(t *testing.T) {
	h := beltHBytes()
	for _, che := range []bool{false, true} {
		enc, e := NewAuthenticatedStream(che, false, h[128:160], h[192:208], 48)
		if e != nil {
			t.Fatal(e)
		}
		enc.AddAAD(h[16:48])
		enc.Update(h[:8])
		enc.Update(h[8:16])
		ct, tag, e := enc.Seal()
		if e != nil {
			t.Fatal(e)
		}
		enc.Close()
		dec, e := NewAuthenticatedStream(che, true, h[128:160], h[192:208], 48)
		if e != nil {
			t.Fatal(e)
		}
		dec.AddAAD(h[16:48])
		if e = dec.Update(ct); e != nil {
			t.Fatal(e)
		}
		bad := append([]byte(nil), tag...)
		bad[0] ^= 1
		if p, e := dec.Open(bad); p != nil || !errors.Is(e, bee2.ErrAuthentication) {
			t.Fatalf("%x %v", p, e)
		}
		dec.Refresh(h[192:208])
		dec.AddAAD(h[16:48])
		dec.Update(ct)
		p, e := dec.Open(tag)
		if e != nil || !bytes.Equal(p, h[:16]) {
			t.Fatal(e)
		}
		dec.Close()
		small, e := NewAuthenticatedStream(che, true, h[128:160], h[192:208], 1)
		if e != nil {
			t.Fatal(e)
		}
		if e = small.Update(ct); !errors.Is(e, bee2.ErrInvalidInput) {
			t.Fatal(e)
		}
		small.Close()
	}
}
func TestAuthenticatedRefreshAndPhases(t *testing.T) {
	h := beltHBytes()
	for _, che := range []bool{false, true} {
		a, e := NewAuthenticatedStream(che, false, h[128:160], h[192:208], 64)
		if e != nil {
			t.Fatal(e)
		}
		a.Update(h[:12])
		if _, _, e = a.Seal(); e != nil {
			t.Fatal(e)
		}
		if e = a.Update(nil); !errors.Is(e, bee2.ErrState) {
			t.Fatal(e)
		}
		if _, e = a.Open(make([]byte, 8)); !errors.Is(e, bee2.ErrState) {
			t.Fatal(e)
		}
		if e = a.Refresh(h[208:224]); e != nil {
			t.Fatal(e)
		}
		b, e := NewAuthenticatedStream(che, false, h[128:160], h[208:224], 64)
		if e != nil {
			t.Fatal(e)
		}
		a.AddAAD(h[32:48])
		b.AddAAD(h[32:48])
		a.Update(h[:16])
		b.Update(h[:16])
		x, xt, e := a.Seal()
		if e != nil {
			t.Fatal(e)
		}
		y, yt, e := b.Seal()
		if e != nil || !bytes.Equal(x, y) || !bytes.Equal(xt, yt) {
			t.Fatal(e)
		}
		a.Close()
		b.Close()
		if e = a.Update(nil); !errors.Is(e, bee2.ErrClosed) {
			t.Fatal(e)
		}
	}
}
