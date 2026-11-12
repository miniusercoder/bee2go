package bign

import (
	"bytes"
	"encoding/hex"
	"github.com/miniusercoder/bee2go/v3/belt"
	"testing"
)

func katHex(t *testing.T, s string) []byte {
	t.Helper()
	b, e := hex.DecodeString(s)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func TestProfile96UpstreamDeterministicKAT(t *testing.T) {
	priv := katHex(t, "b1e1cddfcf5dd7ba278390f292eeb72b661b79922933bfb9")
	pub := katHex(t, "4ced8fbba1842be58b4c0444f359cb14c6f2ce13b710f1172d2c962f53d13115de14e56d9eb2628c9a884f668059eea5")
	want := katHex(t, "d95def43f36a4c73d19399b79fb0c692cf44d615cce5f45d474e7593d30e70b9b0c3")
	hash, e := belt.Hash(katHex(t, "b194bac80a08f53b366d008e58"))
	if e != nil {
		t.Fatal(e)
	}
	digest := hash[:24]
	derived, e := Profile96.PublicKey(priv)
	if e != nil || !bytes.Equal(derived, pub) {
		t.Fatalf("public %x %v", derived, e)
	}
	if e = Profile96.ValidateKeyPair(priv, pub); e != nil {
		t.Fatal(e)
	}
	if e = Profile96.ValidatePublicKey(pub); e != nil {
		t.Fatal(e)
	}
	sig, e := Profile96.SignDigestDeterministic(digest, priv, nil)
	if e != nil || !bytes.Equal(sig, want) {
		t.Fatalf("signature %x %v", sig, e)
	}
	if e = Profile96.VerifyDigest(digest, want, pub); e != nil {
		t.Fatal(e)
	}
	want[0] ^= 1
	if e = Profile96.VerifyDigest(digest, want, pub); e == nil {
		t.Fatal("accepted modified signature")
	}
}
func TestProfile128UpstreamVerificationAndUnwrap(t *testing.T) {
	priv := katHex(t, "1f66b5b84b7339674533f0329c74f21834281fed0732429e0c79235fc273e269")
	pub := katHex(t, "bd1a5650179d79e03fcee49d4c2bd5ddf54ce46d0cf11e4ff87bf7a890857fd07ac6a60361e8c8173491686d461b2826190c2eda5909054a9ab84d2ab9d99a90")
	sig := katHex(t, "e36b7f0377ae4c524027c387fadf1b20ce72f1530b71f2b5fd3a8c584fe2e1aed20082e30c8af65011f4fb54649dfd3d")
	digest, e := belt.Hash(katHex(t, "b194bac80a08f53b366d008e58"))
	if e != nil {
		t.Fatal(e)
	}
	got, e := Profile128.PublicKey(priv)
	if e != nil || !bytes.Equal(got, pub) {
		t.Fatalf("public %x %v", got, e)
	}
	if e = Profile128.ValidateKeyPair(priv, pub); e != nil {
		t.Fatal(e)
	}
	if e = Profile128.VerifyDigest(digest, sig, pub); e != nil {
		t.Fatal(e)
	}
	token := katHex(t, "9b4ea669dabdf100a7d4b6e6eb76ee5251912531f426750aac8a9dbb51c54d8deb9289b50a46952d0531861e45a8814b008fdc65de9ff1fa2a1f16b6a280e957a814")
	header := katHex(t, "5be3d61217b96181fe6786ad716b890b")
	want := katHex(t, "b194bac80a08f53b366d008e584a5de48504")
	out, e := Profile128.UnwrapKey(token, header, priv)
	if e != nil || !bytes.Equal(out, want) {
		t.Fatalf("unwrap %x %v", out, e)
	}
}
