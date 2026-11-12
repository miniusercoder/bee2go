package belt

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestWBLKAT(t *testing.T) {
	h := beltHBytes()
	w, e := NewWBL(h[128:160])
	if e != nil {
		t.Fatal(e)
	}
	defer w.Close()
	buf := append([]byte(nil), h[:48]...)
	if e = w.Encrypt(buf); e != nil {
		t.Fatal(e)
	}
	want, _ := hex.DecodeString("49a38ee108d6c742e52b774f00a6ef98b106cbd13ea4fb0680323051bc04df76e487b055c69bcf541176169f1dc9f6c8")
	if !bytes.Equal(buf, want) {
		t.Fatalf("%x", buf)
	}
	if e = w.Decrypt(buf); e != nil || !bytes.Equal(buf, h[:48]) {
		t.Fatal(e)
	}
}
func TestWBLSplitDecrypt(t *testing.T) {
	h := beltHBytes()
	w, e := NewWBL(h[128:160])
	if e != nil {
		t.Fatal(e)
	}
	defer w.Close()
	b := bytes.Clone(h[:47])
	w.Encrypt(b)
	if e = w.DecryptSplit(b[:31], b[31:]); e != nil || !bytes.Equal(b, h[:47]) {
		t.Fatalf("%x %v", b, e)
	}
}
func TestWBLContinueReference(t *testing.T) {
	h := beltHBytes()
	w, e := NewWBL(h[128:160])
	if e != nil {
		t.Fatal(e)
	}
	defer w.Close()
	b := bytes.Clone(h[:48])
	if e = w.Continue(b); e != nil {
		t.Fatal(e)
	}
	if e = w.Continue(b); e != nil {
		t.Fatal(e)
	}
	want, _ := hex.DecodeString("c5a0ec0a63ce6fa6484f5ec23ce38544e08843a68fafd72f14141effc4591e8ecfb798ce7696fb80c80b782247514ee9")
	if !bytes.Equal(b, want) {
		t.Fatalf("%x", b)
	}
}
