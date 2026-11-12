package btok

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestCertificateChain(t *testing.T) {
	key, _ := hex.DecodeString("1F66B5B84B7339674533F0329C74F21834281FED0732429E0C79235FC273E269")
	base := Certificate{Authority: "BYCA0000", Holder: "BYCA0000", From: [6]byte{2, 2, 0, 7, 0, 7}, Until: [6]byte{9, 9, 0, 7, 0, 7}}
	root, issued, e := WrapCertificate(base, key)
	if e != nil {
		t.Fatal(e)
	}
	if e = CheckCertificate(issued); e != nil {
		t.Fatal(e)
	}
	decoded, e := UnwrapCertificate(root, issued.PublicKey)
	if e != nil || !bytes.Equal(decoded.PublicKey, issued.PublicKey) {
		t.Fatal(e)
	}
	if n, e := CertificateLength(append(root, 0)); e != nil || n != len(root) {
		t.Fatal(n, e)
	}
	if e = MatchCertificate(root, key); e != nil {
		t.Fatal(e)
	}
	child := Certificate{Authority: "BYCA0000", Holder: "BYCA1000", PublicKey: issued.PublicKey, From: [6]byte{2, 2, 0, 7, 1, 2}, Until: [6]byte{3, 0, 0, 1, 0, 1}}
	if e = CheckCertificateForIssuer(child, issued); e != nil {
		t.Fatal(e)
	}
	cert, c, e := IssueCertificate(child, root, key)
	if e != nil {
		t.Fatal(e)
	}
	if e = ValidateCertificate(cert, root, nil); e != nil {
		t.Fatal(e)
	}
	v, e := ValidateCertificateForIssuer(cert, issued, nil)
	if e != nil || v.Holder != c.Holder {
		t.Fatal(e)
	}
	badDate := [6]byte{9, 8, 0, 1, 0, 1}
	if e = ValidateCertificate(cert, root, &badDate); e == nil {
		t.Fatal("expired")
	}
	cert[len(cert)-1] ^= 1
	if _, e = UnwrapCertificate(cert, issued.PublicKey); e == nil {
		t.Fatal("bad signature")
	}
	if e = ValidateCertificate(cert, root, nil); e == nil {
		t.Fatal("bad certificate")
	}
	if e = MatchCertificate(root, make([]byte, 31)); e == nil {
		t.Fatal("key length")
	}
}
func TestCertificateKeySizesAndFailures(t *testing.T) {
	for _, n := range []int{24, 32, 48, 64} {
		key := make([]byte, n)
		key[0] = 1
		c := Certificate{Authority: "BYCA0000", Holder: "BYCA0000", From: [6]byte{2, 2, 0, 7, 0, 7}, Until: [6]byte{9, 9, 0, 7, 0, 7}}
		der, issued, e := WrapCertificate(c, key)
		if e != nil {
			t.Fatalf("key %d: %v", n, e)
		}
		if len(issued.PublicKey) != 2*n {
			t.Fatal(n)
		}
		if _, e = UnwrapCertificate(der, issued.PublicKey); e != nil {
			t.Fatal(n, e)
		}
		if _, e = CertificateLength(der[:len(der)-1]); e == nil {
			t.Fatal("truncated")
		}
		if e = MatchCertificate(der, key); e != nil {
			t.Fatal(e)
		}
		bad := append([]byte(nil), key...)
		bad[0] = 2
		if e = MatchCertificate(der, bad); e == nil {
			t.Fatal("wrong key")
		}
		badCert := issued
		badCert.Authority = "invalid"
		if e = CheckCertificate(badCert); e == nil {
			t.Fatal("short authority")
		}
		badCert = issued
		badCert.From = [6]byte{9, 9, 1, 9, 3, 9}
		if e = CheckCertificate(badCert); e == nil {
			t.Fatal("invalid date")
		}
	}
}
func FuzzCertificate(f *testing.F) {
	f.Add([]byte{0x7f, 0x21, 0})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 4096 {
			return
		}
		_, _ = CertificateLength(data)
		_, _ = UnwrapCertificate(data, nil)
		_ = ValidateCertificate(data, data, nil)
		_ = MatchCertificate(data, make([]byte, 32))
	})
}
func TestCertificateCVector(t *testing.T) {
	der, _ := hex.DecodeString("7F2181B37F4E7D5F290100420842594341303030307F494F060A2A7000020022652D02010341000000000000000000000000000000000000000000000000000000000000000000936A510418CF291E52F608C4663991785D83D651A3C9E45C9FD616FB3CFCF76B5F200842594341303030305F25060202000700075F24060909000700075F373050A23A428FEF6341A69465E02443E9CE58503D2F01E545AA1BB8ED91BDDCAC02901105432DEE1D294326538746BDA8A0")
	pub, _ := hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000000936A510418CF291E52F608C4663991785D83D651A3C9E45C9FD616FB3CFCF76B")
	c, e := UnwrapCertificate(der, pub)
	if e != nil || c.Holder != "BYCA0000" || !bytes.Equal(c.PublicKey, pub) {
		t.Fatal(e)
	}
	key := make([]byte, 32)
	key[0] = 1
	if e = MatchCertificate(der, key); e != nil {
		t.Fatal(e)
	}
	if e = ValidateCertificate(der, der, nil); e != nil {
		t.Fatal(e)
	}
}
