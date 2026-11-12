package belt

import (
	"bytes"
	"encoding/hex"
	"errors"
	bee2 "github.com/miniusercoder/bee2go/v3"
	"testing"
)

func TestCBCStreamingCTSAndRefresh(t *testing.T) {
	h := beltHBytes()
	s, e := NewCBC(h[128:160], h[192:208], false)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	buf := append([]byte(nil), h[:33]...)
	if e = s.Update(buf[:16]); e != nil {
		t.Fatal(e)
	}
	if e = s.Final(buf[16:]); e != nil {
		t.Fatal(e)
	}
	want, e := CBCEncrypt(h[:33], h[128:160], h[192:208])
	if e != nil || !bytes.Equal(buf, want) {
		t.Fatalf("%x %x %v", buf, want, e)
	}
	if e = s.Update(make([]byte, 16)); !errors.Is(e, bee2.ErrState) {
		t.Fatal(e)
	}
	if e = s.Refresh(h[208:224]); e != nil {
		t.Fatal(e)
	}
	buf = append(buf[:0], h[:32]...)
	s.Final(buf)
	want, _ = CBCEncrypt(h[:32], h[128:160], h[208:224])
	if !bytes.Equal(buf, want) {
		t.Fatal("refresh")
	}
}
func TestCTSBounds(t *testing.T) {
	h := beltHBytes()
	for _, n := range []int{15, 16, 17, 31, 32, 33} {
		for _, cbc := range []bool{false, true} {
			var s *Stream
			var e error
			var want []byte
			if cbc {
				s, e = NewCBC(h[128:160], h[192:208], false)
			} else {
				s, e = NewECB(h[128:160], false)
			}
			if e != nil {
				t.Fatal(e)
			}
			buf := bytes.Clone(h[:n])
			e = s.Final(buf)
			s.Close()
			if n < 16 {
				if !errors.Is(e, bee2.ErrInvalidInput) {
					t.Fatal(n, e)
				}
				continue
			}
			if cbc {
				want, e = CBCEncrypt(h[:n], h[128:160], h[192:208])
			} else {
				want, e = ECBEncrypt(h[:n], h[128:160])
			}
			if e != nil || !bytes.Equal(buf, want) {
				t.Fatalf("%d %v", n, e)
			}
		}
	}
}
func TestRefreshMatchesNewState(t *testing.T) {
	h := beltHBytes()
	for _, newFn := range []func([]byte, []byte, bool) (*Stream, error){NewCBC, NewCFB, func(k, iv []byte, _ bool) (*Stream, error) { return NewCTR(k, iv) }, NewBDE} {
		a, e := newFn(h[128:160], h[192:208], false)
		if e != nil {
			t.Fatal(e)
		}
		b, e := newFn(h[128:160], h[208:224], false)
		if e != nil {
			t.Fatal(e)
		}
		tmp := bytes.Clone(h[:32])
		if e = a.Update(tmp); e != nil {
			t.Fatal(e)
		}
		if e = a.Refresh(h[208:224]); e != nil {
			t.Fatal(e)
		}
		x, y := bytes.Clone(h[:32]), bytes.Clone(h[:32])
		if e = a.Final(x); e != nil {
			t.Fatal(e)
		}
		if e = b.Final(y); e != nil || !bytes.Equal(x, y) {
			t.Fatalf("refresh %x %x %v", x, y, e)
		}
		a.Close()
		b.Close()
	}
}
func TestStreamKATFragments(t *testing.T) {
	h := beltHBytes()
	for _, tc := range []struct {
		new  func([]byte, []byte) (*Stream, error)
		want string
	}{{func(k, iv []byte) (*Stream, error) { return NewCFB(k, iv, false) }, "c31e490a90efa374626cc99e4b7b8540a6e48685464a5a06849c9ca769a1b0ae55c2cc5939303ec832dd2fe16c8e5a1b"}, {NewCTR, "52c9af96ff50f64435fc43def56bd797d5b5b1ff79fb41257ab9cdf6e63e81f8f00341473eae409833622de05213773a"}} {
		s, e := tc.new(h[128:160], h[192:208])
		if e != nil {
			t.Fatal(e)
		}
		buf := bytes.Clone(h[:48])
		if e = s.Update(buf[:15]); e != nil {
			t.Fatal(e)
		}
		if e = s.Update(buf[15:22]); e != nil {
			t.Fatal(e)
		}
		if e = s.Final(buf[22:]); e != nil {
			t.Fatal(e)
		}
		want, _ := hex.DecodeString(tc.want)
		if !bytes.Equal(buf, want) {
			t.Fatalf("%x", buf)
		}
		s.Close()
	}
}
