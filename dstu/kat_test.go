package dstu

import (
	"encoding/hex"
	"testing"
)

func reverseHex(t *testing.T, s string) []byte {
	t.Helper()
	b, e := hex.DecodeString(s)
	if e != nil {
		t.Fatal(e)
	}
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	return b
}
func TestUpstreamSignature(t *testing.T) {
	p, e := Standard("1.2.804.2.1.1.1.1.3.1.1.1.2.0")
	if e != nil {
		t.Fatal(e)
	}
	defer p.Close()
	hash := reverseHex(t, "003A2EB95B7180166DDF73532EEB76EDAEF52247FF")
	pub := append(reverseHex(t, "057DE7FDE023FF929CB6AC785CE4B79CF64ABDC2DA"), reverseHex(t, "03E85444324BCF06AD85ABF6AD7B5F34770532B9AA")...)
	sig := reverseHex(t, "000000000000000000000002100D86957331832B8E8C230F5BD6A332B3615ACA00000000000000000000000274EA2C0CAA014A0D80A424F59ADE7A93068D08A7")
	if e = p.Verify(hash, sig, pub); e != nil {
		t.Fatal(e)
	}
	hash[0] ^= 1
	if e = p.Verify(hash, sig, pub); e == nil {
		t.Fatal("tampered hash")
	}
}
