package g12s

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"os"
	"strconv"
	"strings"
	"testing"
)

func TestPinnedCFixtures(t *testing.T) {
	f, e := os.Open("testdata/fixtures.txt")
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	scan := bufio.NewScanner(f)
	rows := 0
	seed := make([]byte, 64)
	for i := range seed {
		seed[i] = byte(i)
	}
	for scan.Scan() {
		v := strings.Fields(scan.Text())
		if len(v) != 12 {
			t.Fatalf("fixture columns: %d", len(v))
		}
		rows++
		t.Run(v[0], func(t *testing.T) {
			unhex := func(s string) []byte {
				b, e := hex.DecodeString(s)
				if e != nil {
					t.Fatal(e)
				}
				return b
			}
			number := func(s string) uint64 {
				n, e := strconv.ParseUint(s, 10, 32)
				if e != nil {
					t.Fatal(e)
				}
				return n
			}
			check := func(name string, got []byte, want string) {
				t.Helper()
				if !bytes.Equal(got, unhex(want)) {
					t.Errorf("%s differs from C", name)
				}
			}
			p, e := Standard(v[0])
			if e != nil {
				t.Fatal(e)
			}
			defer p.Close()
			d, e := p.Data()
			if e != nil {
				t.Fatal(e)
			}
			if uint64(d.L) != number(v[1]) || uint64(d.Cofactor) != number(v[2]) {
				t.Fatal("metadata mismatch")
			}
			for i, a := range [][]byte{d.P[:], d.A[:], d.B[:], d.Q[:], d.X[:], d.Y[:]} {
				check("parameter", a, v[3+i])
			}
			priv, pub, e := p.GenerateKey(bytes.NewReader(seed))
			if e != nil {
				t.Fatal(e)
			}
			check("private key", priv, v[9])
			check("public key", pub, v[10])
			sig, e := p.Sign(seed[:d.L/8], priv, bytes.NewReader(seed))
			if e != nil {
				t.Fatal(e)
			}
			check("signature", sig, v[11])
			if e = p.Verify(seed[:d.L/8], sig, pub); e != nil {
				t.Fatal(e)
			}
			sig[0] ^= 1
			if e = p.Verify(seed[:d.L/8], sig, pub); e == nil {
				t.Fatal("accepted changed signature")
			}
		})
	}
	if e = scan.Err(); e != nil {
		t.Fatal(e)
	}
	if rows != 8 {
		t.Fatalf("expected 8 curves, got %d", rows)
	}
}
