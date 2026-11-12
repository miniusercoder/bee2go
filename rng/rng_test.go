package rng

import (
	"errors"
	bee2 "github.com/miniusercoder/bee2go/v3"
	"testing"
)

func TestOwners(t *testing.T) {
	a, e := New()
	if e != nil {
		t.Fatal(e)
	}
	defer a.Close()
	b, e := New()
	if e != nil {
		t.Fatal(e)
	}
	defer b.Close()
	a.Close()
	a.Close()
	if _, e = a.Read(nil); !errors.Is(e, bee2.ErrClosed) {
		t.Fatal(e)
	}
	out := make([]byte, 32)
	if n, e := b.Read(out); e != nil || n != 32 {
		t.Fatal(n, e)
	}
	if e = b.Rekey(); e != nil {
		t.Fatal(e)
	}
}
func TestEntropy(t *testing.T) {
	b := make([]byte, 32)
	n, e := ReadEntropy(b, "sys")
	if e != nil || n != 32 {
		t.Fatal(n, e)
	}
	if _, e = ReadEntropy(b, "unknown"); e == nil {
		t.Fatal("accepted unknown source")
	}
	if TestFIPS1(make([]byte, 2499)) {
		t.Fatal("short FIPS sample")
	}
}
