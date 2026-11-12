package bign

import (
	"bytes"
	"errors"
	bee2 "github.com/miniusercoder/bee2go/v3"
	"testing"
)

func TestParamsDERRoundTrip(t *testing.T) {
	for _, oid := range []string{Curve256v1, Curve384v1, Curve512v1} {
		p, e := StandardParams(oid)
		if e != nil {
			t.Fatal(e)
		}
		der, e := p.DER()
		if e != nil {
			t.Fatal(e)
		}
		q, e := ParamsFromDER(der)
		if e != nil {
			t.Fatal(e)
		}
		again, _ := q.DER()
		if !bytes.Equal(der, again) {
			t.Fatal("DER mismatch")
		}
		q.Close()
		p.Close()
		p.Close()
		if _, e = p.DER(); !errors.Is(e, bee2.ErrClosed) {
			t.Fatal(e)
		}
	}
	if p, e := ParamsFromDER([]byte{0x30, 0x80}); e == nil {
		p.Close()
		t.Fatal("accepted malformed DER")
	}
}
func TestProfilesDigestAndKeypairs(t *testing.T) {
	for _, pr := range []Profile{Profile96, Profile128, Profile192, Profile256} {
		priv, pub, e := pr.GenerateKey(nil)
		if e != nil {
			t.Fatal(pr, e)
		}
		if e = pr.ValidateKeyPair(priv, pub); e != nil {
			t.Fatal(e)
		}
		digest := make([]byte, pr.DigestSize())
		sig, e := pr.SignDigestDeterministic(digest, priv, nil)
		if e != nil {
			t.Fatal(pr, e)
		}
		if e = pr.VerifyDigest(digest, sig, pub); e != nil {
			t.Fatal(pr, e)
		}
		sig[0] ^= 1
		if e = pr.VerifyDigest(digest, sig, pub); !errors.Is(e, bee2.ErrAuthentication) {
			t.Fatal(pr, e)
		}
		if _, e = pr.SignDigestDeterministic(digest[:len(digest)-1], priv, nil); !errors.Is(e, bee2.ErrInvalidInput) {
			t.Fatal(e)
		}
		pub[0] ^= 1
		if e = pr.ValidateKeyPair(priv, pub); e == nil {
			t.Fatal("mismatched pair")
		}
	}
}
func TestGeneralSignDHTransportAndEntropy(t *testing.T) {
	p, e := StandardParams(Curve256v1)
	if e != nil {
		t.Fatal(e)
	}
	defer p.Close()
	a, A, e := GenerateKey(p, nil)
	if e != nil {
		t.Fatal(e)
	}
	b, B, e := GenerateKey(p, nil)
	if e != nil {
		t.Fatal(e)
	}
	x, e := DH(p, a, B, 32)
	if e != nil {
		t.Fatal(e)
	}
	y, e := DH(p, b, A, 32)
	if e != nil || !bytes.Equal(x, y) {
		t.Fatal(e)
	}
	oid, _ := OIDToDER(OIDBeltHash)
	h := make([]byte, 32)
	sig, e := SignDigest(p, oid, h, a, nil)
	if e != nil {
		t.Fatal(e)
	}
	if e = VerifyDigest(p, oid, h, sig, A); e != nil {
		t.Fatal(e)
	}
	token, e := WrapKey(p, []byte("0123456789abcdef"), nil, B, nil)
	if e != nil {
		t.Fatal(e)
	}
	key, e := UnwrapKey(p, token, nil, b)
	if e != nil || string(key) != "0123456789abcdef" {
		t.Fatal(e)
	}
	token[0] ^= 1
	if key, e = UnwrapKey(p, token, nil, b); e == nil || key != nil {
		t.Fatal("unauthenticated key")
	}
	if key, pub, e := GenerateKey(p, bytes.NewReader(nil)); e == nil || key != nil || pub != nil {
		t.Fatal("entropy failure ignored")
	}
}
func TestGenerateParamsNeedsCalculator(t *testing.T) {
	if p, e := GenerateParams(ParamsSeed{Level: 128}, nil, nil); e == nil || p != nil {
		t.Fatal("missing calculator")
	}
}
func TestIdentitySignatures(t *testing.T) {
	p, e := StandardParams(Curve256v1)
	if e != nil {
		t.Fatal(e)
	}
	defer p.Close()
	priv, pub, e := GenerateKey(p, nil)
	if e != nil {
		t.Fatal(e)
	}
	oid, _ := OIDToDER(OIDBeltHash)
	id := bytes.Repeat([]byte{1}, 32)
	digest := bytes.Repeat([]byte{2}, 32)
	cert, e := SignDigestDeterministic(p, oid, id, priv, nil)
	if e != nil {
		t.Fatal(e)
	}
	a, A, e := ExtractIdentity(p, oid, id, cert, pub)
	if e != nil {
		t.Fatal(e)
	}
	for _, random := range []bool{false, true} {
		var sig []byte
		if random {
			sig, e = SignIdentityDigest(p, oid, id, digest, a, nil)
		} else {
			sig, e = SignIdentityDigestDeterministic(p, oid, id, digest, a, nil)
		}
		if e != nil {
			t.Fatal(e)
		}
		if e = VerifyIdentityDigest(p, oid, id, digest, sig, A, pub); e != nil {
			t.Fatal(e)
		}
		sig[0] ^= 1
		if e = VerifyIdentityDigest(p, oid, id, digest, sig, A, pub); e == nil {
			t.Fatal("tampered identity signature")
		}
	}
}
func paramSeed() ParamsSeed {
	p := bytes.Repeat([]byte{255}, 32)
	p[0] = 0x43
	a := append([]byte(nil), p...)
	a[0] = 0x40
	return ParamsSeed{Level: 128, P: p, A: a, Seed: [8]byte{0x50, 0x38, 1}}
}
func TestGenerateParamsCallbacks(t *testing.T) {
	q := []byte{0x07, 0x66, 0x3d, 0x26, 0x99, 0xbf, 0x5a, 0x7e, 0xfc, 0x4d, 0xfb, 0x0d, 0xd6, 0x8e, 0x5c, 0xd9, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255}
	seen := 0
	next := 0
	p, e := GenerateParams(paramSeed(), func(c CurveCandidate) ([]byte, error) {
		if c.Seed[0] != 0x5e {
			next++
			return nil, ErrNoResult
		}
		return q, nil
	}, func(c CurveCandidate) error { seen++; return nil })
	if e != nil {
		t.Fatal(e)
	}
	defer p.Close()
	standard, _ := StandardParams(Curve256v1)
	defer standard.Close()
	d, _ := p.DER()
	want, _ := standard.DER()
	if !bytes.Equal(d, want) || next == 0 || seen < 2 {
		t.Fatal("parameter generation did not follow upstream seed sequence")
	}
	marker := errors.New("cancelled")
	if p, e = GenerateParams(paramSeed(), func(CurveCandidate) ([]byte, error) { return nil, nil }, func(CurveCandidate) error { return marker }); p != nil || !errors.Is(e, marker) {
		t.Fatal(e)
	}
	for _, calc := range []OrderCalculator{func(CurveCandidate) ([]byte, error) { return nil, marker }, func(CurveCandidate) ([]byte, error) { return []byte{1}, nil }, func(CurveCandidate) ([]byte, error) { panic("test") }} {
		if p, e = GenerateParams(paramSeed(), calc, nil); p != nil || e == nil {
			t.Fatal("callback error ignored")
		}
	}
}
