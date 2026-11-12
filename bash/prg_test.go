package bash

import (
	"bytes"
	"encoding/hex"
	"errors"
	bee2 "github.com/miniusercoder/bee2go/v3"
	"testing"
)

func TestPRGFragmentsAndState(t *testing.T) {
	key := make([]byte, 16)
	a, e := NewPRG(128, 1, nil, key)
	if e != nil {
		t.Fatal(e)
	}
	defer a.Close()
	b, e := NewPRG(128, 1, nil, key)
	if e != nil {
		t.Fatal(e)
	}
	defer b.Close()
	if e = a.AbsorbStep(nil); !errors.Is(e, bee2.ErrState) {
		t.Fatalf("step before start %v", e)
	}
	a.Absorb([]byte("abcdef"))
	b.AbsorbStart()
	b.AbsorbStep([]byte("abc"))
	b.AbsorbStep([]byte("def"))
	x := make([]byte, 32)
	y := make([]byte, 32)
	a.Squeeze(x)
	b.SqueezeStart()
	b.SqueezeStep(y[:11])
	b.SqueezeStep(y[11:])
	if !bytes.Equal(x, y) {
		t.Fatal("fragment mismatch")
	}
	a.Close()
	if e = a.Ratchet(); !errors.Is(e, bee2.ErrClosed) {
		t.Fatal(e)
	}
	if _, e = NewPRG(128, 1, []byte{1}, key); !errors.Is(e, bee2.ErrInvalidInput) {
		t.Fatal(e)
	}
}

func TestPRGUpstreamRestartKAT(t *testing.T) {
	h := beltHBytes()
	p, e := NewPRG(256, 2, nil, h[:32])
	if e != nil {
		t.Fatal(e)
	}
	p.Absorb(h[32:127])
	p.Ratchet()
	key := make([]byte, 16)
	p.Squeeze(key)
	p.Close()
	want, _ := hex.DecodeString("71cc358a0d5082173de04803f7e905cb")
	if !bytes.Equal(key, want) {
		t.Fatalf("%x", key)
	}
	p, e = NewPRG(128, 1, h[128:144], key)
	if e != nil {
		t.Fatal(e)
	}
	defer p.Close()
	if e = p.Restart(h[144:148], nil); e != nil {
		t.Fatal(e)
	}
	b := append([]byte(nil), h[160:183]...)
	if e = p.Encrypt(b); e != nil {
		t.Fatal(e)
	}
	want, _ = hex.DecodeString("28fe0998bfc010f13b260685a27afb36ccf580f753521b")
	if !bytes.Equal(b, want) {
		t.Fatalf("%x", b)
	}
}
func TestPRGParametersAndPhases(t *testing.T) {
	for _, l := range []int{128, 192, 256} {
		for _, d := range []int{1, 2} {
			p, e := NewPRG(l, d, nil, nil)
			if e != nil {
				t.Fatal(e)
			}
			if e = p.EncryptStart(); !errors.Is(e, bee2.ErrState) {
				t.Fatal(e)
			}
			if e = p.DecryptStep(nil); !errors.Is(e, bee2.ErrState) {
				t.Fatal(e)
			}
			if e = p.Restart(nil, make([]byte, l/8)); e != nil {
				t.Fatal(e)
			}
			if e = p.EncryptStart(); e != nil {
				t.Fatal(e)
			}
			if e = p.SqueezeStep(nil); !errors.Is(e, bee2.ErrState) {
				t.Fatal(e)
			}
			p.Close()
		}
	}
	for _, tc := range []struct{ l, d, ann, key int }{{64, 1, 0, 0}, {128, 0, 0, 0}, {128, 3, 0, 0}, {128, 1, 1, 0}, {128, 1, 64, 0}, {128, 1, 0, 4}, {128, 1, 0, 17}, {128, 1, 0, 64}} {
		if p, e := NewPRG(tc.l, tc.d, make([]byte, tc.ann), make([]byte, tc.key)); !errors.Is(e, bee2.ErrInvalidInput) {
			if p != nil {
				p.Close()
			}
			t.Fatalf("%+v %v", tc, e)
		}
	}
}
func TestPRGCommandsDistinct(t *testing.T) {
	a, _ := NewPRG(128, 2, nil, nil)
	b, _ := NewPRG(128, 2, nil, nil)
	defer a.Close()
	defer b.Close()
	a.Absorb([]byte("abc"))
	a.Absorb([]byte("def"))
	b.Absorb([]byte("abcdef"))
	x, y := make([]byte, 32), make([]byte, 32)
	a.Squeeze(x)
	b.Squeeze(y)
	if bytes.Equal(x, y) {
		t.Fatal("separate commands must differ from fragments")
	}
}
func FuzzPRGFragments(f *testing.F) {
	f.Add([]byte("fragment"), uint8(3), uint8(1), uint8(0))
	f.Fuzz(func(t *testing.T, data []byte, split, lid, did uint8) {
		if len(data) > 512 {
			return
		}
		levels := []int{128, 192, 256}
		a, e := NewPRG(levels[int(lid)%3], int(did)%2+1, nil, nil)
		if e != nil {
			t.Fatal(e)
		}
		defer a.Close()
		b, e := NewPRG(levels[int(lid)%3], int(did)%2+1, nil, nil)
		if e != nil {
			t.Fatal(e)
		}
		defer b.Close()
		n := int(split) % (len(data) + 1)
		a.Absorb(data)
		b.AbsorbStart()
		b.AbsorbStep(data[:n])
		b.AbsorbStep(data[n:])
		x, y := make([]byte, 32), make([]byte, 32)
		a.Squeeze(x)
		b.Squeeze(y)
		if !bytes.Equal(x, y) {
			t.Fatal("fragment mismatch")
		}
	})
}
func TestPRGEncryptKAT(t *testing.T) {
	h := beltHBytes()
	key, _ := hex.DecodeString("71cc358a0d5082173de04803f7e905cb")
	p, e := NewPRG(128, 1, h[128:144], key)
	if e != nil {
		t.Fatal(e)
	}
	buf := bytes.Clone(h[160:183])
	p.EncryptStart()
	p.EncryptStep(buf[:7])
	p.EncryptStep(buf[7:])
	want, _ := hex.DecodeString("51ed3b28d345ffd1ad22815b86ecc17c278c8fe8920214")
	if !bytes.Equal(buf, want) {
		t.Fatalf("%x", buf)
	}
	p.Close()
	p, e = NewPRG(128, 1, h[128:144], key)
	if e != nil {
		t.Fatal(e)
	}
	defer p.Close()
	p.DecryptStart()
	p.DecryptStep(buf[:13])
	p.DecryptStep(buf[13:])
	if !bytes.Equal(buf, h[160:183]) {
		t.Fatal("decrypt")
	}
}
func TestPRGSpongeKAT(t *testing.T) {
	h := beltHBytes()
	for _, tc := range []struct {
		n    int
		want string
	}{{0, "36fa075ec15721f250b9a641a8cb99a333a9ee7ba8586d0646cbac3686c03df3"}, {127, "c930ff427307420da6e4182969aa1ffc3310179b8a0edb3e20bec285b568ba17"}, {128, "92ad1402c2007191f2f7cfad6a2f8807bb0c50f73dff95ef1b8af08504d54007"}, {150, "48db61832ca1009003bc0d8bde67893a9dc683c48a5bc23ac884eb4613b480a6"}} {
		p, e := NewPRG(128, 2, nil, nil)
		if e != nil {
			t.Fatal(e)
		}
		p.Absorb(h[:tc.n])
		got := make([]byte, 32)
		p.Squeeze(got)
		p.Close()
		want, _ := hex.DecodeString(tc.want)
		if !bytes.Equal(got, want) {
			t.Fatalf("%d %x", tc.n, got)
		}
	}
}
