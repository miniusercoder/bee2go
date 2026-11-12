package bign

import (
	"bytes"
	"errors"
	"fmt"
	bee2 "github.com/miniusercoder/bee2go/v3"
	"testing"
)

func TestProfileDeterministicMatchesGeneral(t *testing.T) {
	for _, tc := range []struct {
		p          Profile
		curve, oid string
	}{{Profile128, Curve256v1, OIDBeltHash}, {Profile192, Curve384v1, "1.2.112.0.2.0.34.101.77.12"}, {Profile256, Curve512v1, "1.2.112.0.2.0.34.101.77.13"}} {
		t.Run(fmt.Sprint(tc.p), func(t *testing.T) {
			params, e := StandardParams(tc.curve)
			if e != nil {
				t.Fatal(e)
			}
			defer params.Close()
			oid, e := OIDToDER(tc.oid)
			if e != nil {
				t.Fatal(e)
			}
			priv, pub, e := tc.p.GenerateKey(bytes.NewReader(bytes.Repeat([]byte{byte(tc.p)}, 64)))
			if e != nil {
				t.Fatal(e)
			}
			digest := make([]byte, tc.p.DigestSize())
			for i := range digest {
				digest[i] = byte(i + 1)
			}
			for _, extra := range [][]byte{nil, []byte("context")} {
				a, e := tc.p.SignDigestDeterministic(digest, priv, extra)
				if e != nil {
					t.Fatal(e)
				}
				b, e := SignDigestDeterministic(params, oid, digest, priv, extra)
				if e != nil || !bytes.Equal(a, b) {
					t.Fatalf("profile %x general %x: %v", a, b, e)
				}
				if e = VerifyDigest(params, oid, digest, a, pub); e != nil {
					t.Fatal(e)
				}
				if e = tc.p.VerifyDigest(digest, b, pub); e != nil {
					t.Fatal(e)
				}
				changed := bytes.Clone(digest)
				changed[0] ^= 1
				if e = tc.p.VerifyDigest(changed, a, pub); e == nil {
					t.Fatal("accepted modified digest")
				}
			}
		})
	}
}
func TestProfileDHTransportBothRoles(t *testing.T) {
	for _, p := range []Profile{Profile128, Profile192, Profile256} {
		t.Run(fmt.Sprint(p), func(t *testing.T) {
			a, A, e := p.GenerateKey(bytes.NewReader(bytes.Repeat([]byte{0x11}, 64)))
			if e != nil {
				t.Fatal(e)
			}
			b, B, e := p.GenerateKey(bytes.NewReader(bytes.Repeat([]byte{0x22}, 64)))
			if e != nil {
				t.Fatal(e)
			}
			for _, n := range []int{0, 1, p.DigestSize(), 2 * p.DigestSize()} {
				x, e := p.DH(a, B, n)
				if e != nil {
					t.Fatal(n, e)
				}
				y, e := p.DH(b, A, n)
				if e != nil || !bytes.Equal(x, y) || len(x) != n {
					t.Fatalf("DH %d %v", n, e)
				}
			}
			for i, party := range []struct{ priv, pub []byte }{{a, A}, {b, B}} {
				key := bytes.Repeat([]byte{byte(i + 1)}, 16+i)
				header := bytes.Repeat([]byte{byte(i + 3)}, 16)
				token, e := p.WrapKey(key, header, party.pub, bytes.NewReader(bytes.Repeat([]byte{byte(i + 4)}, 64)))
				if e != nil {
					t.Fatal(e)
				}
				if len(token) != len(key)+p.DigestSize()+16 {
					t.Fatal("token size")
				}
				out, e := p.UnwrapKey(token, header, party.priv)
				if e != nil || !bytes.Equal(out, key) {
					t.Fatal(e)
				}
				token[len(token)-1] ^= 1
				if out, e = p.UnwrapKey(token, header, party.priv); e == nil || out != nil {
					t.Fatal("tamper", e)
				}
			}
		})
	}
}
func TestProfileValidationAndEntropy(t *testing.T) {
	for _, p := range []Profile{Profile96, Profile128, Profile192, Profile256} {
		priv, pub, e := p.GenerateKey(bytes.NewReader(bytes.Repeat([]byte{1}, 64)))
		if e != nil {
			t.Fatal(e)
		}
		if a, b, e := p.GenerateKey(bytes.NewReader(nil)); !errors.Is(e, bee2.ErrRandom) || a != nil || b != nil {
			t.Fatal(p, e)
		}
		digest := make([]byte, p.DigestSize())
		if sig, e := p.SignDigest(digest, priv, bytes.NewReader(nil)); !errors.Is(e, bee2.ErrRandom) || sig != nil {
			t.Fatal(p, e)
		}
		if _, e = p.SignDigestDeterministic(digest[:len(digest)-1], priv, nil); !errors.Is(e, bee2.ErrInvalidInput) {
			t.Fatal(p, e)
		}
		if e = p.ValidateKeyPair(priv[:len(priv)-1], pub); !errors.Is(e, bee2.ErrInvalidInput) {
			t.Fatal(p, e)
		}
		if _, e = p.PublicKey(priv[:len(priv)-1]); !errors.Is(e, bee2.ErrInvalidInput) {
			t.Fatal(p, e)
		}
		if e = p.VerifyDigest(digest, make([]byte, 1), pub); !errors.Is(e, bee2.ErrInvalidInput) {
			t.Fatal(p, e)
		}
		if p != Profile96 {
			if _, e = p.DH(priv, pub, 2*len(priv)+1); !errors.Is(e, bee2.ErrInvalidInput) {
				t.Fatal(p, e)
			}
			if _, e = p.WrapKey(make([]byte, 16), nil, pub, bytes.NewReader(nil)); !errors.Is(e, bee2.ErrRandom) {
				t.Fatal(p, e)
			}
			if _, e = p.WrapKey(make([]byte, 15), nil, pub, nil); !errors.Is(e, bee2.ErrInvalidInput) {
				t.Fatal(p, e)
			}
			if _, e = p.UnwrapKey(make([]byte, 1), nil, priv); !errors.Is(e, bee2.ErrInvalidInput) {
				t.Fatal(p, e)
			}
		}
	}
}
func TestGeneralClosedAndInvalidArguments(t *testing.T) {
	p, e := StandardParams(Curve256v1)
	if e != nil {
		t.Fatal(e)
	}
	priv, pub, e := GenerateKey(p, bytes.NewReader(bytes.Repeat([]byte{0x41}, 64)))
	if e != nil {
		t.Fatal(e)
	}
	oid, e := OIDToDER(OIDBeltHash)
	if e != nil {
		t.Fatal(e)
	}
	digest := make([]byte, 32)
	if _, e = SignDigestDeterministic(p, oid, digest[:31], priv, nil); !errors.Is(e, bee2.ErrInvalidInput) {
		t.Fatal(e)
	}
	if _, e = DH(p, priv, pub, 65); !errors.Is(e, bee2.ErrInvalidInput) {
		t.Fatal(e)
	}
	if _, e = WrapKey(p, make([]byte, 16), make([]byte, 15), pub, nil); !errors.Is(e, bee2.ErrInvalidInput) {
		t.Fatal(e)
	}
	if _, e = UnwrapKey(p, make([]byte, 63), nil, priv); !errors.Is(e, bee2.ErrInvalidInput) {
		t.Fatal(e)
	}
	if _, _, e = GenerateKey(p, bytes.NewReader(nil)); !errors.Is(e, bee2.ErrRandom) {
		t.Fatal(e)
	}
	if _, e = SignDigest(p, oid, digest, priv, bytes.NewReader(nil)); !errors.Is(e, bee2.ErrRandom) {
		t.Fatal(e)
	}
	if _, e = WrapKey(p, make([]byte, 16), nil, pub, bytes.NewReader(nil)); !errors.Is(e, bee2.ErrRandom) {
		t.Fatal(e)
	}
	p.Close()
	p.Close()
	checks := []func() error{func() error { _, e := p.DER(); return e }, p.Validate, func() error { _, e := PublicKey(p, priv); return e }, func() error { _, e := DH(p, priv, pub, 32); return e }, func() error { _, e := SignDigestDeterministic(p, oid, digest, priv, nil); return e }, func() error { return VerifyDigest(p, oid, digest, make([]byte, 48), pub) }, func() error { _, e := WrapKey(p, make([]byte, 16), nil, pub, nil); return e }, func() error { _, e := UnwrapKey(p, make([]byte, 64), nil, priv); return e }}
	for i, check := range checks {
		if e = check(); !errors.Is(e, bee2.ErrClosed) {
			t.Fatalf("closed %d: %v", i, e)
		}
	}
}
func TestProfileInvalidPointsAndTransport(t *testing.T) {
	for _, p := range []Profile{Profile128, Profile192, Profile256} {
		priv, pub, e := p.GenerateKey(bytes.NewReader(bytes.Repeat([]byte{0x31}, 64)))
		if e != nil {
			t.Fatal(e)
		}
		bad := bytes.Clone(pub)
		for i := range bad {
			bad[i] = 0
		}
		if e = p.ValidatePublicKey(bad); e == nil {
			t.Fatal(p, "zero point")
		}
		if out, e := p.DH(priv, bad, 16); e == nil || out != nil {
			t.Fatal(p, "DH invalid peer", e)
		}
		if out, e := p.WrapKey(make([]byte, 16), make([]byte, 15), pub, nil); !errors.Is(e, bee2.ErrInvalidInput) || out != nil {
			t.Fatal(p, e)
		}
		key := bytes.Repeat([]byte{7}, 16)
		header := bytes.Repeat([]byte{8}, 16)
		token, e := p.WrapKey(key, header, pub, bytes.NewReader(bytes.Repeat([]byte{9}, 64)))
		if e != nil {
			t.Fatal(e)
		}
		header[0] ^= 1
		if out, e := p.UnwrapKey(token, header, priv); e == nil || out != nil {
			t.Fatal(p, "wrong header", e)
		}
	}
	if _, e := Profile96.DH(make([]byte, 24), make([]byte, 48), 16); !errors.Is(e, bee2.ErrInvalidInput) {
		t.Fatal(e)
	}
	if _, e := Profile96.WrapKey(make([]byte, 16), nil, make([]byte, 48), nil); !errors.Is(e, bee2.ErrInvalidInput) {
		t.Fatal(e)
	}
}
