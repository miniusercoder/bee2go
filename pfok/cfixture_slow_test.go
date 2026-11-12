//go:build slow

package pfok

import (
	"bytes"
	"encoding/hex"
	"os"
	"strconv"
	"strings"
	"testing"
)

func TestCGeneratedSeed766(t *testing.T) {
	raw, e := os.ReadFile("testdata/generated766.txt")
	if e != nil {
		t.Fatal(e)
	}
	v := strings.Fields(string(raw))
	if len(v) != 5 {
		t.Fatal("invalid fixture")
	}
	s := Seed{L: 766}
	if e = s.Adjust(); e != nil {
		t.Fatal(e)
	}
	p, e := Generate(s)
	if e != nil {
		t.Fatal(e)
	}
	n := func(x string) uint64 {
		v, e := strconv.ParseUint(x, 10, 64)
		if e != nil {
			t.Fatal(e)
		}
		return v
	}
	decode := func(x string) []byte {
		v, e := hex.DecodeString(x)
		if e != nil {
			t.Fatal(e)
		}
		return v
	}
	if p.L != n(v[0]) || p.R != n(v[1]) || p.N != n(v[2]) || !bytes.Equal(p.P[:], decode(v[3])) || !bytes.Equal(p.G[:], decode(v[4])) {
		t.Fatal("generation differs from C fixture")
	}
	if e = p.Validate(); e != nil {
		t.Fatal(e)
	}
}
