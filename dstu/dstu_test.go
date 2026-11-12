package dstu

import (
	"bytes"
	"fmt"
	"testing"
)

func TestPointAndSignature(t *testing.T) {
	p, e := Standard("1.2.804.2.1.1.1.1.3.1.1.1.2.0")
	if e != nil {
		t.Fatal(e)
	}
	defer p.Close()
	if e = p.Validate(); e != nil {
		t.Fatal(e)
	}
	point, e := p.GeneratePoint(nil)
	if e != nil {
		t.Fatal(e)
	}
	if e = p.ValidatePoint(point); e != nil {
		t.Fatal(e)
	}
	compressed, e := p.Compress(point)
	if e != nil {
		t.Fatal(e)
	}
	restored, e := p.Recover(compressed)
	if e != nil || !bytes.Equal(point, restored) {
		t.Fatal("point roundtrip", e)
	}
	priv, pub, e := p.GenerateKey(nil)
	if e != nil {
		t.Fatal(e)
	}
	hash := make([]byte, 32)
	hash[0] = 1
	sig, e := p.Sign(hash, priv, 512, nil)
	if e != nil {
		t.Fatal(e)
	}
	if e = p.Verify(hash, sig, pub); e != nil {
		t.Fatal(e)
	}
	sig[0] ^= 1
	if e = p.Verify(hash, sig, pub); e == nil {
		t.Fatal("bad signature")
	}
	if e = p.ValidatePoint(nil); e == nil {
		t.Fatal("bad point")
	}
}

func TestStandardCurves(t *testing.T) {
	for i := 0; i < 10; i++ {
		name := fmt.Sprintf("1.2.804.2.1.1.1.1.3.1.1.1.2.%d", i)
		p, e := Standard(name)
		if e != nil {
			t.Fatal(name, e)
		}
		if i > 0 {
			point, e := p.GeneratePoint(nil)
			if e != nil {
				t.Fatal(name, e)
			}
			if e = p.SetBasePoint(point); e != nil {
				t.Fatal(name, e)
			}
		}
		if e = p.Validate(); e != nil {
			t.Fatal(name, e)
		}
		priv, pub, e := p.GenerateKey(nil)
		if e != nil {
			t.Fatal(name, e)
		}
		hash := []byte{1, 2, 3}
		sig, e := p.Sign(hash, priv, 1024, nil)
		if e != nil {
			t.Fatal(name, e)
		}
		if e = p.Verify(hash, sig, pub); e != nil {
			t.Fatal(name, e)
		}
		p.Close()
	}
}
func TestClosedParams(t *testing.T) {
	var p *Params
	if e := p.Validate(); e == nil {
		t.Fatal("nil params")
	}
	p, e := Standard("1.2.804.2.1.1.1.1.3.1.1.1.2.0")
	if e != nil {
		t.Fatal(e)
	}
	p.Close()
	if e = p.Validate(); e == nil {
		t.Fatal("closed params")
	}
}
func TestEmptyDigest(t *testing.T) {
	p, e := Standard("1.2.804.2.1.1.1.1.3.1.1.1.2.0")
	if e != nil {
		t.Fatal(e)
	}
	defer p.Close()
	priv, pub, e := p.GenerateKey(nil)
	if e != nil {
		t.Fatal(e)
	}
	sig, e := p.Sign(nil, priv, 512, nil)
	if e != nil {
		t.Fatal(e)
	}
	if e = p.Verify(nil, sig, pub); e != nil {
		t.Fatal(e)
	}
}
func TestParameterData(t *testing.T) {
	p, e := Standard("1.2.804.2.1.1.1.1.3.1.1.1.2.0")
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
	data.Field[0] = 0
	if _, e = FromData(data); e == nil {
		t.Fatal("invalid field")
	}
}
