package bels

import (
	"bytes"
	"errors"
	bee2 "github.com/miniusercoder/bee2go/v3"
	"testing"
)

func TestRecoverRejectsSwappedMemberParams(t *testing.T) {
	common, _ := Standard(16, 0)
	a, _ := Standard(16, 1)
	b, _ := Standard(16, 2)
	s, e := Split(bytes.Repeat([]byte{9}, 16), common, []Params{a, b}, 2, nil)
	if e != nil {
		t.Fatal(e)
	}
	if secret, e := Recover(s, common, []Params{b, a}, 2); secret != nil || !errors.Is(e, bee2.ErrInvalidInput) {
		t.Fatalf("member substitution returned %x, %v", secret, e)
	}
}
func TestShareOwnsMetadataAndImports(t *testing.T) {
	common, _ := Standard(16, 0)
	a, _ := Standard(16, 1)
	b, _ := Standard(16, 2)
	secret := bytes.Repeat([]byte{7}, 16)
	s, e := Split(secret, common, []Params{a, b}, 2, nil)
	if e != nil {
		t.Fatal(e)
	}
	clear(common)
	clear(a)
	clear(b)
	c, m0 := s[0].Parameters()
	_, m1 := s[1].Parameters()
	value := s[0].Bytes()
	imported, e := NewShare(value, c, m0)
	if e != nil {
		t.Fatal(e)
	}
	clear(value)
	got, e := Recover([]Share{imported, s[1]}, c, []Params{m0, m1}, 2)
	if e != nil || !bytes.Equal(got, secret) {
		t.Fatal(e)
	}
	clear(m0)
	_, original := s[0].Parameters()
	if bytes.Equal(m0, original) {
		t.Fatal("Parameters returned alias")
	}
	standard, e := ShareStandard(secret, 2, 2, nil)
	if e != nil {
		t.Fatal(e)
	}
	for i := range standard {
		wire := standard[i].Bytes()
		s, e := NewStandardShare(wire)
		if e != nil {
			t.Fatal(e)
		}
		id, ok := s.Identifier()
		if !ok || id != byte(i+1) {
			t.Fatal("identifier lost")
		}
		clear(wire)
		standard[i] = s
	}
	got, e = RecoverStandard(standard, 2)
	if e != nil || !bytes.Equal(got, secret) {
		t.Fatal(e)
	}
	if _, e = NewShare(make([]byte, 15), c, original); e == nil {
		t.Fatal("short share")
	}
	if _, e = NewStandardShare(nil); e == nil {
		t.Fatal("empty share")
	}
	if _, e = NewStandardShare(make([]byte, 17)); e == nil {
		t.Fatal("zero identifier")
	}
}
