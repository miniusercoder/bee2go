package belt

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestKeyOperationsKAT(t *testing.T) {
	h := beltHBytes()
	check := func(g []byte, e error, w string) {
		t.Helper()
		want, _ := hex.DecodeString(w)
		if e != nil || !bytes.Equal(g, want) {
			t.Fatalf("got %x: %v", g, e)
		}
	}
	g, e := MAC(h[:48], h[128:160])
	check(g, e, "2dab59771b4b16d0")
	g, e = HMAC(h[192:224], h[128:160])
	check(g, e, "41ffe8645aec0612e952d2cdf8dd508f3e4a1d9b53f6a1db293b19fe76b1879f")
	level := make([]byte, 12)
	level[0] = 1
	g, e = KRP(h[128:160], level, h[32:48], 16)
	check(g, e, "6bbbc2336670d31ab83daa90d52c0541")
	g, e = PBKDF2([]byte("B194BAC80A08F53B"), 10000, h[192:200])
	check(g, e, "3d331bbbb1fbbb40e4bf22f6cb9a689ef13a77dc09ecf93291bfe42439a72e7d")
	tok, e := KWPWrap(h[:32], h[32:48], h[128:160])
	if e != nil {
		t.Fatal(e)
	}
	g, e = KWPUnwrap(tok, h[32:48], h[128:160])
	if e != nil || !bytes.Equal(g, h[:32]) {
		t.Fatal(e)
	}
}
func TestKWPKAT(t *testing.T) {
	h := beltHBytes()
	out, e := KWPWrap(h[:32], h[32:48], h[128:160])
	want, _ := hex.DecodeString("49a38ee108d6c742e52b774f00a6ef98b106cbd13ea4fb0680323051bc04df76e487b055c69bcf541176169f1dc9f6c8")
	if e != nil || !bytes.Equal(out, want) {
		t.Fatalf("%x %v", out, e)
	}
}
func TestKRPAllLengthsKAT(t *testing.T) {
	h := beltHBytes()
	level := make([]byte, 12)
	level[0] = 1
	k, e := NewKRP(h[128:160], level)
	if e != nil {
		t.Fatal(e)
	}
	defer k.Close()
	for _, tc := range []struct {
		n    int
		want string
	}{{16, "6bbbc2336670d31ab83daa90d52c0541"}, {24, "9a2532a18cbaf145398d5a95feea6c825b9c197156a00275"}, {32, "76e166e6ab21256b6739397b672b879614b81cf05955fc3ab09343a745c48f77"}} {
		want, _ := hex.DecodeString(tc.want)
		got, e := k.Derive(tc.n, h[32:48])
		if e != nil || !bytes.Equal(got, want) {
			t.Fatalf("%d %x %v", tc.n, got, e)
		}
	}
}
