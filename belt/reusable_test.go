package belt

import (
	"bytes"
	"reflect"
	"testing"
)

func TestReusableStates(t *testing.T) {
	h := beltHBytes()
	s, e := NewSDE(h[128:160])
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	b := bytes.Clone(h[:48])
	if e = s.Encrypt(b, h[192:208]); e != nil {
		t.Fatal(e)
	}
	want, e := SDEEncrypt(h[:48], h[128:160], h[192:208])
	if e != nil || !bytes.Equal(b, want) {
		t.Fatal(e)
	}
	s.Decrypt(b, h[192:208])
	if !bytes.Equal(b, h[:48]) {
		t.Fatal("SDE decrypt")
	}
	f, e := NewFMT(10, 10, h[128:160])
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	v := []uint16{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}
	if e = f.Encrypt(v, h[192:208]); e != nil {
		t.Fatal(e)
	}
	if !reflect.DeepEqual(v, []uint16{6, 9, 3, 4, 7, 7, 0, 3, 5, 2}) {
		t.Fatal(v)
	}
	f.Decrypt(v, h[192:208])
	if !reflect.DeepEqual(v, []uint16{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}) {
		t.Fatal(v)
	}
	level := make([]byte, 12)
	level[0] = 1
	k, e := NewKRP(h[128:160], level)
	if e != nil {
		t.Fatal(e)
	}
	defer k.Close()
	got, e := k.Derive(24, h[32:48])
	want, e2 := KRP(h[128:160], level, h[32:48], 24)
	if e != nil || e2 != nil || !bytes.Equal(got, want) {
		t.Fatal(e, e2)
	}
}
