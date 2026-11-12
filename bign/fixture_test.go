package bign

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"testing"
)

func readCVectors(t *testing.T) map[string][]byte {
	t.Helper()
	f, e := os.Open("testdata/vectors.txt")
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	m := map[string][]byte{}
	s := bufio.NewScanner(f)
	for s.Scan() {
		key, val, ok := strings.Cut(s.Text(), "=")
		if !ok {
			t.Fatal("invalid fixture line")
		}
		v, e := hex.DecodeString(val)
		if e != nil {
			t.Fatal(e)
		}
		if _, exists := m[key]; exists {
			t.Fatalf("duplicate fixture %s", key)
		}
		m[key] = v
	}
	if e = s.Err(); e != nil {
		t.Fatal(e)
	}
	return m
}
func TestSeededCFixtures(t *testing.T) {
	v := readCVectors(t)
	h := katHex(t, "b194bac80a08f53b366d008e584a5de48504fa9d1bb6c7ac252e72c202fdce0d5be3d61217b96181fe6786ad716b890b5cb0c0ff33c356b835c405aed8e07f99e12bdc1ae28257ec703fccf095ee8df1c1ab76389fe678caf7c6f860d5bb9c4ff33c657b637c306add4ea7799eb23d313e98b56e27d3bccf591e181f4c5ab793")
	seed := make([]byte, 64)
	for i := range seed {
		seed[i] = byte(i)
	}
	for _, tc := range []struct {
		profile    Profile
		curve, oid string
	}{{Profile96, "", ""}, {Profile128, Curve256v1, OIDBeltHash}, {Profile192, Curve384v1, "1.2.112.0.2.0.34.101.77.12"}, {Profile256, Curve512v1, "1.2.112.0.2.0.34.101.77.13"}} {
		t.Run(fmt.Sprint(tc.profile), func(t *testing.T) {
			expected := func(name string) []byte {
				t.Helper()
				key := fmt.Sprintf("%d.%s", tc.profile, name)
				out, ok := v[key]
				if !ok {
					t.Fatalf("missing %s", key)
				}
				return out
			}
			check := func(name string, got []byte, e error) {
				t.Helper()
				want := expected(name)
				if e != nil || !bytes.Equal(got, want) {
					t.Fatalf("%s got %x, want %x: %v", name, got, want, e)
				}
			}
			entropy := func() *bytes.Reader { return bytes.NewReader(seed) }
			n := tc.profile.DigestSize()
			hash := h[:n]
			priv, pub, e := tc.profile.GenerateKey(entropy())
			if e != nil {
				t.Fatal(e)
			}
			check("profile_priv", priv, nil)
			check("profile_pub", pub, nil)
			sig, e := tc.profile.SignDigest(hash, priv, entropy())
			check("profile_sign", sig, e)
			sig2, e := tc.profile.SignDigestDeterministic(hash, priv, nil)
			check("profile_sign2", sig2, e)
			if e = tc.profile.VerifyDigest(hash, expected("profile_sign"), pub); e != nil {
				t.Fatal(e)
			}
			bad := bytes.Clone(sig)
			bad[0] ^= 1
			if e = tc.profile.VerifyDigest(hash, bad, pub); e == nil {
				t.Fatal("accepted altered signature")
			}
			if tc.profile == Profile96 {
				return
			}
			shared, e := tc.profile.DH(priv, pub, 2*n)
			check("profile_dh", shared, e)
			token, e := tc.profile.WrapKey(h[:18], h[32:48], pub, entropy())
			check("profile_wrap", token, e)
			out, e := tc.profile.UnwrapKey(expected("profile_wrap"), h[32:48], priv)
			if e != nil || !bytes.Equal(out, h[:18]) {
				t.Fatal("profile unwrap", e)
			}
			p, e := StandardParams(tc.curve)
			if e != nil {
				t.Fatal(e)
			}
			defer p.Close()
			oid, e := OIDToDER(tc.oid)
			if e != nil {
				t.Fatal(e)
			}
			a, A, e := GenerateKey(p, entropy())
			if e != nil {
				t.Fatal(e)
			}
			check("generic_priv", a, nil)
			check("generic_pub", A, nil)
			shared, e = DH(p, a, A, 2*n)
			check("generic_dh", shared, e)
			sig, e = SignDigest(p, oid, hash, a, entropy())
			check("generic_sign", sig, e)
			sig2, e = SignDigestDeterministic(p, oid, hash, a, nil)
			check("generic_sign2", sig2, e)
			if e = VerifyDigest(p, oid, hash, expected("generic_sign"), A); e != nil {
				t.Fatal(e)
			}
			token, e = WrapKey(p, h[:18], h[32:48], A, entropy())
			check("generic_wrap", token, e)
			out, e = UnwrapKey(p, expected("generic_wrap"), h[32:48], a)
			if e != nil || !bytes.Equal(out, h[:18]) {
				t.Fatal("generic unwrap", e)
			}
			idhash := h[64 : 64+n]
			cert, e := SignDigestDeterministic(p, oid, idhash, a, nil)
			check("id_cert", cert, e)
			ia, iA, e := ExtractIdentity(p, oid, idhash, expected("id_cert"), A)
			if e != nil {
				t.Fatal(e)
			}
			check("id_priv", ia, nil)
			check("id_pub", iA, nil)
			is, e := SignIdentityDigest(p, oid, idhash, hash, ia, entropy())
			check("id_sign", is, e)
			is2, e := SignIdentityDigestDeterministic(p, oid, idhash, hash, ia, nil)
			check("id_sign2", is2, e)
			for _, want := range [][]byte{expected("id_sign"), expected("id_sign2")} {
				if e = VerifyIdentityDigest(p, oid, idhash, hash, want, iA, A); e != nil {
					t.Fatal(e)
				}
			}
			is[0] ^= 1
			if e = VerifyIdentityDigest(p, oid, idhash, hash, is, iA, A); e == nil {
				t.Fatal("accepted altered identity signature")
			}
			token[0] ^= 1
			if out, e = UnwrapKey(p, token, h[32:48], a); e == nil || out != nil {
				t.Fatal("accepted altered token", e)
			}
		})
	}
}
func TestMalformedOIDs(t *testing.T) {
	for _, s := range []string{"", "x", "1", ".1.2", "1..2", "1.2.", "3.1.2", "1.40.2", "1.2.3\x00.4"} {
		if der, e := OIDToDER(s); e == nil {
			t.Errorf("accepted %q as %x", s, der)
		}
	}
}
func TestMalformedDERSigningOID(t *testing.T) {
	p, e := StandardParams(Curve256v1)
	if e != nil {
		t.Fatal(e)
	}
	defer p.Close()
	seed := make([]byte, 64)
	a, A, e := GenerateKey(p, bytes.NewReader(seed))
	if e != nil {
		t.Fatal(e)
	}
	digest := make([]byte, 32)
	sig := make([]byte, 48)
	for _, oid := range [][]byte{nil, {0x06}, {0x04, 0x01, 0x2a}, {0x06, 0x81, 0xff}, {0x06, 0x02, 0x2a}} {
		if out, e := SignDigestDeterministic(p, oid, digest, a, nil); e == nil || out != nil {
			t.Fatalf("accepted signing oid %x", oid)
		}
		if e = VerifyDigest(p, oid, digest, sig, A); e == nil {
			t.Fatalf("accepted verify oid %x", oid)
		}
	}
}
