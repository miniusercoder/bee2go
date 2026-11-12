package stb99

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"os"
	"strconv"
	"strings"
	"testing"
)

func TestCParameterFixtures(t *testing.T) {
	f, e := os.Open("testdata/fixtures.txt")
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	seeds, params := 0, 0
	number := func(s string) uint64 {
		n, e := strconv.ParseUint(s, 10, 64)
		if e != nil {
			t.Fatal(e)
		}
		return n
	}
	decode := func(s string) []byte {
		b, e := hex.DecodeString(s)
		if e != nil {
			t.Fatal(e)
		}
		return b
	}
	for sc.Scan() {
		v := strings.Fields(sc.Text())
		switch v[0] {
		case "S":
			if len(v) != 61 {
				t.Fatal("invalid seed fixture")
			}
			seeds++
			l := number(v[1])
			s := Seed{L: l}
			if e = s.Adjust(); e != nil {
				t.Fatal(l, e)
			}
			if e = s.Validate(); e != nil {
				t.Fatal(l, e)
			}
			for i, x := range s.ZI {
				if uint64(x) != number(v[2+i]) {
					t.Fatal(l, "zi", i)
				}
			}
			for i, x := range s.DI {
				if x != number(v[33+i]) {
					t.Fatal(l, "di", i)
				}
			}
			for i, x := range s.RI {
				if x != number(v[51+i]) {
					t.Fatal(l, "ri", i)
				}
			}
			for _, x := range []uint16{1, 65256} {
				q := s
				q.ZI[0] = x
				if e = q.Validate(); e != nil {
					t.Fatalf("%d zi %d: %v", l, x, e)
				}
			}
			for _, x := range []uint16{0, 65257, 65535} {
				q := s
				q.ZI[0] = x
				if e = q.Validate(); e == nil {
					t.Fatalf("%d accepted zi %d", l, x)
				}
			}
			for _, delta := range []int64{-1, 1} {
				q := s
				q.L = uint64(int64(l) + delta)
				if e = q.Validate(); e == nil {
					t.Fatal("invalid l accepted", q.L)
				}
			}
			q := s
			q.RI[0]++
			if e = q.Validate(); e == nil {
				t.Fatal("invalid chain accepted", l)
			}
		case "P":
			if len(v) != 8 {
				t.Fatal("invalid params fixture")
			}
			params++
			p, _, e := Standard(v[1])
			if e != nil {
				t.Fatal(e)
			}
			if p.L != number(v[2]) || p.R != number(v[3]) || !bytes.Equal(p.P[:], decode(v[4])) || !bytes.Equal(p.Q[:], decode(v[5])) || !bytes.Equal(p.A[:], decode(v[6])) || !bytes.Equal(p.D[:], decode(v[7])) {
				t.Fatal("params differ", v[1])
			}
			bad := p
			bad.R++
			if e = bad.Validate(); e == nil {
				t.Fatal("invalid r accepted", v[1])
			}
		default:
			t.Fatal("unexpected fixture")
		}
	}
	if e = sc.Err(); e != nil {
		t.Fatal(e)
	}
	if seeds != 10 || params != 4 {
		t.Fatalf("seed rows=%d params=%d", seeds, params)
	}
	if _, e := Generate(Seed{}); e == nil {
		t.Fatal("invalid generation seed")
	}
}
