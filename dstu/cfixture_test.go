package dstu

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
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
	digest := append([]byte(nil), seed[:32]...)
	for scan.Scan() {
		v := strings.Fields(scan.Text())
		if len(v) != 16 {
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
			for i := 0; i < 4; i++ {
				if uint64(d.Field[i]) != number(v[1+i]) {
					t.Fatal("field mismatch")
				}
			}
			if uint64(d.A) != number(v[5]) || uint64(d.Cofactor) != number(v[6]) {
				t.Fatal("coefficients mismatch")
			}
			check("B", d.B[:], v[7])
			check("order", d.N[:], v[8])
			check("standard base", d.Base[:], v[9])
			point, e := p.GeneratePoint(bytes.NewReader(seed))
			if e != nil {
				t.Fatal(e)
			}
			check("point", point, v[10])
			if e = p.SetBasePoint(point); e != nil {
				t.Fatal(e)
			}
			if e = p.Validate(); e != nil {
				t.Fatal(e)
			}
			if e = p.ValidatePoint(point); e != nil {
				t.Fatal(e)
			}
			c, e := p.Compress(point)
			if e != nil {
				t.Fatal(e)
			}
			check("compressed", c, v[11])
			r, e := p.Recover(c)
			if e != nil {
				t.Fatal(e)
			}
			check("recovered", r, v[12])
			priv, pub, e := p.GenerateKey(bytes.NewReader(seed))
			if e != nil {
				t.Fatal(e)
			}
			check("private key", priv, v[13])
			check("public key", pub, v[14])
			sig, e := p.Sign(digest, priv, 1024, bytes.NewReader(seed))
			if e != nil {
				t.Fatal(e)
			}
			check("signature", sig, v[15])
			if e = p.Verify(digest, sig, pub); e != nil {
				t.Fatal(e)
			}
			sig[0] ^= 1
			if e = p.Verify(digest, sig, pub); e == nil {
				t.Fatal("accepted changed signature")
			}
		})
	}
	if e = scan.Err(); e != nil {
		t.Fatal(e)
	}
	if rows != 10 {
		t.Fatal(fmt.Sprintf("expected 10 curves, got %d", rows))
	}
}
