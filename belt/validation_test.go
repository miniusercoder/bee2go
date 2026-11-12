package belt

import (
	"bytes"
	"errors"
	bee2 "github.com/miniusercoder/bee2go/v3"
	"testing"
)

func TestValidation(t *testing.T) {
	for _, n := range []int{0, 15, 17, 23, 25, 31, 33} {
		key := make([]byte, n)
		if _, e := NewBlock(key); !errors.Is(e, bee2.ErrInvalidInput) {
			t.Fatal(n, e)
		}
		if _, e := NewMAC(key); !errors.Is(e, bee2.ErrInvalidInput) {
			t.Fatal(n, e)
		}
		if _, e := NewWBL(key); !errors.Is(e, bee2.ErrInvalidInput) {
			t.Fatal(n, e)
		}
	}
	for _, n := range []int{16, 24, 32} {
		key := make([]byte, n)
		for _, l := range []int{15, 17} {
			if _, e := CBCEncrypt(make([]byte, 16), key, make([]byte, l)); !errors.Is(e, bee2.ErrInvalidInput) {
				t.Fatal(n, l, e)
			}
		}
	}
	key := make([]byte, 16)
	for _, tc := range []struct {
		mod uint32
		v   []uint16
	}{{1, []uint16{0, 0}}, {65537, []uint16{0, 0}}, {2, []uint16{2, 0}}, {2, []uint16{0}}, {2, make([]uint16, 601)}} {
		if _, e := FMTEncrypt(tc.v, tc.mod, key, nil); !errors.Is(e, bee2.ErrInvalidInput) {
			t.Fatalf("%v %v", tc, e)
		}
	}
	for _, mod := range []uint32{2, 65536} {
		src := []uint16{0, uint16(mod - 1)}
		enc, e := FMTEncrypt(src, mod, key, nil)
		if e != nil {
			t.Fatal(e)
		}
		dec, e := FMTDecrypt(enc, mod, key, nil)
		if e != nil || len(dec) != 2 || dec[0] != src[0] || dec[1] != src[1] {
			t.Fatal(e)
		}
	}
	s, e := NewCBC(key, make([]byte, 16), false)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Update(make([]byte, 15)); !errors.Is(e, bee2.ErrInvalidInput) {
		t.Fatal(e)
	}
	s.Close()
	if e = s.Refresh(make([]byte, 16)); !errors.Is(e, bee2.ErrClosed) {
		t.Fatal(e)
	}
	w, e := NewWBL(key)
	if e != nil {
		t.Fatal(e)
	}
	b := make([]byte, 32)
	if e = w.DecryptSplit(b[:20], b[16:]); !errors.Is(e, bee2.ErrInvalidInput) {
		t.Fatal(e)
	}
	w.Close()
	if e = w.Encrypt(b); !errors.Is(e, bee2.ErrClosed) {
		t.Fatal(e)
	}
	if _, e = KWPWrap(make([]byte, 16), make([]byte, 17), key); !errors.Is(e, bee2.ErrInvalidInput) {
		t.Fatal(e)
	}
	_, e = KRP(key, make([]byte, 12), make([]byte, 16), 24)
	if !errors.Is(e, bee2.ErrInvalidInput) {
		t.Fatal(e)
	}
	if !bytes.Equal(key, make([]byte, 16)) {
		t.Fatal("input modified")
	}
}
