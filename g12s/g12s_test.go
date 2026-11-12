package g12s

import (
	"encoding/hex"
	"testing"
)

func decode(t *testing.T, s string) []byte {
	t.Helper()
	b, e := hex.DecodeString(s)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func TestStandardSignature(t *testing.T) {
	p, e := Standard("1.2.643.2.2.35.0")
	if e != nil {
		t.Fatal(e)
	}
	defer p.Close()
	if e = p.Validate(); e != nil {
		t.Fatal(e)
	}
	pub := decode(t, "26f1b489d6701dd185c8413a977b3cbbaf64d1c593d26627dffb101a87ff77da7f2b49e270db6d90d8595bec458b50c58585ba1d4e9b788f6689dbd8e56fd80b")
	for i, j := 0, len(pub)-1; i < j; i, j = i+1, j-1 {
		pub[i], pub[j] = pub[j], pub[i]
	}
	hash := decode(t, "2dfbc1b372d89a1188c09c52e0eec61fce52032ab1022e8e67ece6672b043ee5")
	sig := decode(t, "41aa28d2f1ab148280cd9ed56feda41974053554a42767b83ad043fd39dc049301456c64ba4642a1653c235a98a60249bcd6d3f746b631df928014f6c5bf9c40")
	if e = p.Verify(hash, sig, pub); e != nil {
		t.Fatal(e)
	}
	sig[0] ^= 1
	if e = p.Verify(hash, sig, pub); e == nil {
		t.Fatal("bad signature")
	}
	if e = p.Verify(hash[:1], sig, pub); e == nil {
		t.Fatal("short hash")
	}
	priv, pub, e := p.GenerateKey(nil)
	if e != nil {
		t.Fatal(e)
	}
	sig, e = p.Sign(hash, priv, nil)
	if e != nil {
		t.Fatal(e)
	}
	if e = p.Verify(hash, sig, pub); e != nil {
		t.Fatal(e)
	}
}

func TestStandardSets(t *testing.T) {
	for _, name := range []string{"1.2.643.2.2.35.0", "1.2.643.2.2.35.1", "1.2.643.2.2.35.2", "1.2.643.2.2.35.3", "1.2.643.2.9.1.8.1", "1.2.643.7.1.2.1.2.0", "1.2.643.7.1.2.1.2.1", "1.2.643.7.1.2.1.2.2"} {
		p, e := Standard(name)
		if e != nil {
			t.Fatal(name, e)
		}
		if e = p.Validate(); e != nil {
			t.Fatal(name, e)
		}
		priv, pub, e := p.GenerateKey(nil)
		if e != nil {
			t.Fatal(name, e)
		}
		hash := make([]byte, len(priv))
		hash[0] = 1
		sig, e := p.Sign(hash, priv, nil)
		if e != nil {
			t.Fatal(name, e)
		}
		if e = p.Verify(hash, sig, pub); e != nil {
			t.Fatal(name, e)
		}
		p.Close()
	}
	if _, e := Standard("bad"); e == nil {
		t.Fatal("invalid name")
	}
}
func TestUpstream512(t *testing.T) {
	p, e := Standard("1.2.643.7.1.2.1.2.0")
	if e != nil {
		t.Fatal(e)
	}
	defer p.Close()
	pub := decode(t, "37c7c90cd40b0f5621dc3ac1b751cfa0e2634fa0503b3d52639f5d7fb72afd61ea199441d943ffe7f0c70a2759a3cdb84c114e1f9339fdf27f35eca93677beec115dc5bc96760c7b48598d8ab9e740d4c4a85a65be33c1815b5c320c854621dd5a515856d13314af69bc5b924c8b4ddff75c45415c1d9dd9dd33612cd530efe1")
	for i, j := 0, len(pub)-1; i < j; i, j = i+1, j-1 {
		pub[i], pub[j] = pub[j], pub[i]
	}
	hash := decode(t, "3754f3cfacc9e0615c4f4a7c4d8dab531b09b6f9c170c533a71d147035b0c5917184ee536593f4414339976c647c5d5a407adedb1d560c4fc6777d2972075b8c")
	sig := decode(t, "2f86fa60a081091a23dd795e1e3c689ee512a3c82ee0dcc2643c78eea8fcacd35492558486b20f1c9ec197c90699850260c93bcbcd9c5c3317e19344e173ae361081b394696ffe8e6585e7a9362d26b6325f56778aadbc081c0bfbe933d52ff5823ce288e8c4f362526080df7f70ce406a6eeb1f56919cb92a9853bde73e5b4a")
	if e = p.Verify(hash, sig, pub); e != nil {
		t.Fatal(e)
	}
	for i, j := 0, len(hash)-1; i < j; i, j = i+1, j-1 {
		hash[i], hash[j] = hash[j], hash[i]
	}
	if e = p.Verify(hash, sig, pub); e == nil {
		t.Fatal("reversed digest accepted")
	}
}
func TestClosedParams(t *testing.T) {
	var p *Params
	if e := p.Validate(); e == nil {
		t.Fatal("nil params")
	}
	p, e := Standard("1.2.643.2.2.35.0")
	if e != nil {
		t.Fatal(e)
	}
	p.Close()
	if e = p.Validate(); e == nil {
		t.Fatal("closed params")
	}
}
func TestParameterData(t *testing.T) {
	p, e := Standard("1.2.643.2.2.35.0")
	if e != nil {
		t.Fatal(e)
	}
	defer p.Close()
	data, e := p.Data()
	if e != nil {
		t.Fatal(e)
	}
	q, e := FromData(data)
	if e != nil {
		t.Fatal(e)
	}
	defer q.Close()
	if e = q.Validate(); e != nil {
		t.Fatal(e)
	}
	data.L = 0
	if _, e = FromData(data); e == nil {
		t.Fatal("invalid level")
	}
}
