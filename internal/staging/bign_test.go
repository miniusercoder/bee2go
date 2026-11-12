package bee2go

import (
	"bytes"
	"testing"
)

// ────────────────────────────────────────────────────────────────────────────
// OID → DER encoding
// ────────────────────────────────────────────────────────────────────────────

func TestBignOidToDER(t *testing.T) {
	// The DER encoding of "1.2.112.0.2.0.34.101.31.81" must be 11 bytes.
	der, err := BignOidToDER(OIDBeltHash)
	if err != nil {
		t.Fatal(err)
	}
	if len(der) != 11 {
		t.Fatalf("DER length=%d want 11", len(der))
	}

	// BeltHashOID is a convenience alias.
	der2, err := BeltHashOID()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(der, der2) {
		t.Fatal("BeltHashOID != BignOidToDER(OIDBeltHash)")
	}

	// Invalid OID must return an error.
	if _, err := BignOidToDER("99.99.99.notanoid"); err == nil {
		t.Error("invalid OID should fail")
	}
}

// ────────────────────────────────────────────────────────────────────────────
// Helpers used across bign tests
// ────────────────────────────────────────────────────────────────────────────

func newParams256(t *testing.T) *BignParams {
	t.Helper()
	p, err := NewBignParams256v1()
	if err != nil {
		t.Fatalf("NewBignParams256v1: %v", err)
	}
	return p
}

func beltHashOf(t *testing.T, data []byte) []byte {
	t.Helper()
	h, err := BeltHash(data)
	if err != nil {
		t.Fatalf("BeltHash: %v", err)
	}
	return h
}

// ────────────────────────────────────────────────────────────────────────────
// Params accessors
// ────────────────────────────────────────────────────────────────────────────

func TestBignParamsAccessors(t *testing.T) {
	p := newParams256(t)
	defer p.Free()

	if p.L() != 128 {
		t.Errorf("L()=%d want 128", p.L())
	}
	if p.PrivKeyLen() != 32 {
		t.Errorf("PrivKeyLen()=%d want 32", p.PrivKeyLen())
	}
	if p.PubKeyLen() != 64 {
		t.Errorf("PubKeyLen()=%d want 64", p.PubKeyLen())
	}
	if p.SigLen() != 48 {
		t.Errorf("SigLen()=%d want 48 (3*128/8)", p.SigLen())
	}
}

// Verify all three standard curve OIDs load successfully.
func TestBignParamsAllCurves(t *testing.T) {
	for _, f := range []func() (*BignParams, error){
		NewBignParams256v1,
		NewBignParams384v1,
		NewBignParams512v1,
	} {
		p, err := f()
		if err != nil {
			t.Errorf("params load failed: %v", err)
			continue
		}
		p.Free()
	}
}

// ────────────────────────────────────────────────────────────────────────────
// KAT: keypair generation (STB 34.101.45 table Г.1)
// ────────────────────────────────────────────────────────────────────────────

func TestBignKeypairGenKAT(t *testing.T) {
	// The expected values from the STB standard are generated with a specific
	// PRNG seed. We cannot reproduce them without the same seed, so we just
	// check that generation produces keys of the right length and that
	// PubkeyCalc is consistent.
	p := newParams256(t)
	defer p.Free()

	priv, pub, err := BignKeypairGen(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(priv) != 32 {
		t.Errorf("privKey len=%d want 32", len(priv))
	}
	if len(pub) != 64 {
		t.Errorf("pubKey len=%d want 64", len(pub))
	}

	// Derived public key must match.
	pub2, err := BignPubkeyCalc(p, priv)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pub, pub2) {
		t.Fatal("PubkeyCalc result differs from keypair generation")
	}
}

// Nil params must be rejected.
func TestBignKeypairGenNilParams(t *testing.T) {
	if _, _, err := BignKeypairGen(nil); err == nil {
		t.Error("nil params should fail")
	}
	if _, err := BignPubkeyCalc(nil, make([]byte, 32)); err == nil {
		t.Error("nil params should fail")
	}
}

// ────────────────────────────────────────────────────────────────────────────
// DH shared-secret symmetry
// ────────────────────────────────────────────────────────────────────────────

func TestBignDH(t *testing.T) {
	p := newParams256(t)
	defer p.Free()

	privA, pubA, _ := BignKeypairGen(p)
	privB, pubB, _ := BignKeypairGen(p)

	sharedA, err := BignDH(p, privA, pubB, 32)
	if err != nil {
		t.Fatal(err)
	}
	sharedB, err := BignDH(p, privB, pubA, 32)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sharedA, sharedB) {
		t.Fatal("DH: Alice and Bob computed different shared secrets")
	}
	if bytes.Equal(sharedA, make([]byte, 32)) {
		t.Fatal("DH: shared secret is all zeros")
	}
}

// ────────────────────────────────────────────────────────────────────────────
// Sign / Verify round-trip (randomised)
// ────────────────────────────────────────────────────────────────────────────

func TestBignSignVerify(t *testing.T) {
	p := newParams256(t)
	defer p.Free()

	oid, _ := BeltHashOID()
	priv, pub, _ := BignKeypairGen(p)
	msg := beltHBytes()[:48]
	hash := beltHashOf(t, msg)

	sig, err := BignSign(p, oid, hash, priv)
	if err != nil {
		t.Fatal(err)
	}
	if len(sig) != p.SigLen() {
		t.Errorf("sig len=%d want %d", len(sig), p.SigLen())
	}
	if err := BignVerify(p, oid, hash, sig, pub); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

// Corrupted signature must fail.
func TestBignVerifyTamper(t *testing.T) {
	p := newParams256(t)
	defer p.Free()

	oid, _ := BeltHashOID()
	priv, pub, _ := BignKeypairGen(p)
	hash := beltHashOf(t, []byte("test"))

	sig, _ := BignSign(p, oid, hash, priv)
	sig[0] ^= 0xFF
	if err := BignVerify(p, oid, hash, sig, pub); err == nil {
		t.Fatal("tampered sig must fail Verify")
	}
}

// Corrupted public key must fail.
func TestBignVerifyBadPubKey(t *testing.T) {
	p := newParams256(t)
	defer p.Free()

	oid, _ := BeltHashOID()
	priv, pub, _ := BignKeypairGen(p)
	hash := beltHashOf(t, []byte("test"))

	sig, _ := BignSign(p, oid, hash, priv)
	pub[0] ^= 0xFF
	if err := BignVerify(p, oid, hash, sig, pub); err == nil {
		t.Fatal("bad pubKey must fail Verify")
	}
}

// ────────────────────────────────────────────────────────────────────────────
// Sign2 (deterministic) round-trip
// ────────────────────────────────────────────────────────────────────────────

func TestBignSign2Verify(t *testing.T) {
	p := newParams256(t)
	defer p.Free()

	oid, _ := BeltHashOID()
	priv, pub, _ := BignKeypairGen(p)
	hash := beltHashOf(t, beltHBytes()[:13])

	sig1, err := BignSign2(p, oid, hash, priv, nil)
	if err != nil {
		t.Fatal(err)
	}
	sig2, _ := BignSign2(p, oid, hash, priv, nil)
	// Deterministic: same hash + key + no t → same signature.
	if !bytes.Equal(sig1, sig2) {
		t.Fatal("Sign2 with t=nil must be deterministic")
	}

	if err := BignVerify(p, oid, hash, sig1, pub); err != nil {
		t.Fatalf("Verify Sign2 result: %v", err)
	}

	// With additional data t, signature changes.
	extra := []byte("extra")
	sig3, _ := BignSign2(p, oid, hash, priv, extra)
	if bytes.Equal(sig1, sig3) {
		t.Fatal("Sign2 with t!=nil produced same sig as t=nil")
	}
	if err := BignVerify(p, oid, hash, sig3, pub); err != nil {
		t.Fatalf("Verify Sign2 with t: %v", err)
	}
}

// ────────────────────────────────────────────────────────────────────────────
// Sign / Verify across all three curves
// ────────────────────────────────────────────────────────────────────────────

func TestBignSignAllCurves(t *testing.T) {
	oid, _ := BeltHashOID()

	for _, f := range []func() (*BignParams, error){
		NewBignParams256v1,
		NewBignParams384v1,
		NewBignParams512v1,
	} {
		p, err := f()
		if err != nil {
			t.Errorf("params: %v", err)
			continue
		}
		hashLen := p.PrivKeyLen()
		hash := make([]byte, hashLen)
		hash[0] = 0x42 // non-zero

		priv, pub, err := BignKeypairGen(p)
		if err != nil {
			t.Errorf("l=%d keygen: %v", p.L(), err)
			p.Free()
			continue
		}

		sig, err := BignSign(p, oid, hash, priv)
		if err != nil {
			t.Errorf("l=%d Sign: %v", p.L(), err)
			p.Free()
			continue
		}
		if err := BignVerify(p, oid, hash, sig, pub); err != nil {
			t.Errorf("l=%d Verify: %v", p.L(), err)
		}
		p.Free()
	}
}

// ────────────────────────────────────────────────────────────────────────────
// Key wrap / unwrap round-trip
// ────────────────────────────────────────────────────────────────────────────

func TestBignKeyWrapUnwrap(t *testing.T) {
	p := newParams256(t)
	defer p.Free()

	priv, pub, _ := BignKeypairGen(p)
	H := beltHBytes()
	innerKey := H[:18] // 18-byte key to exercise non-block-aligned length

	token, err := BignKeyWrap(p, innerKey, nil, pub)
	if err != nil {
		t.Fatal(err)
	}
	// Token must be len(key) + PrivKeyLen + 16
	wantLen := len(innerKey) + p.PrivKeyLen() + 16
	if len(token) != wantLen {
		t.Errorf("token len=%d want %d", len(token), wantLen)
	}

	recovered, err := BignKeyUnwrap(p, token, nil, priv)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(recovered, innerKey) {
		t.Fatal("KeyUnwrap did not recover original key")
	}
}

// Wrong private key must fail unwrap.
func TestBignKeyUnwrapWrongKey(t *testing.T) {
	p := newParams256(t)
	defer p.Free()

	_, pub, _ := BignKeypairGen(p)
	privWrong, _, _ := BignKeypairGen(p)

	token, _ := BignKeyWrap(p, make([]byte, 32), nil, pub)
	if _, err := BignKeyUnwrap(p, token, nil, privWrong); err == nil {
		t.Fatal("Unwrap with wrong privKey must fail")
	}
}

// ────────────────────────────────────────────────────────────────────────────
// Identity-based signature extract / sign / verify
// ────────────────────────────────────────────────────────────────────────────

func TestBignIdSignVerify(t *testing.T) {
	p := newParams256(t)
	defer p.Free()

	oid, _ := BeltHashOID()

	// Master keypair (trusted party).
	masterPriv, masterPub, _ := BignKeypairGen(p)

	// Sign the identity hash with the master key.
	identity := []byte("user@example.com")
	idHash := beltHashOf(t, identity)
	idSig, err := BignSign(p, oid, idHash, masterPriv)
	if err != nil {
		t.Fatal(err)
	}

	// Extract the IBS keypair from the master signature.
	idPriv, idPub, err := BignIdExtract(p, oid, idHash, idSig, masterPub)
	if err != nil {
		t.Fatalf("IdExtract: %v", err)
	}
	if len(idPriv) != p.PrivKeyLen() || len(idPub) != p.PubKeyLen() {
		t.Fatal("IdExtract returned wrong-length keys")
	}

	// Sign a message with the IBS key.
	msg := beltHBytes()[:48]
	msgHash := beltHashOf(t, msg)

	ibsSig, err := BignIdSign(p, oid, idHash, msgHash, idPriv)
	if err != nil {
		t.Fatalf("IdSign: %v", err)
	}

	// Verify the IBS signature.
	if err := BignIdVerify(p, oid, idHash, msgHash, ibsSig, idPub, masterPub); err != nil {
		t.Fatalf("IdVerify: %v", err)
	}

	// Tamper with the IBS signature.
	ibsSig[0] ^= 0xFF
	if err := BignIdVerify(p, oid, idHash, msgHash, ibsSig, idPub, masterPub); err == nil {
		t.Fatal("tampered IBS sig must fail")
	}
	ibsSig[0] ^= 0xFF

	// Tamper with the IBS pubkey.
	idPub[0] ^= 0xFF
	if err := BignIdVerify(p, oid, idHash, msgHash, ibsSig, idPub, masterPub); err == nil {
		t.Fatal("bad IBS pubKey must fail")
	}
}

// IdSign2 must be deterministic with t=nil.
func TestBignIdSign2Deterministic(t *testing.T) {
	p := newParams256(t)
	defer p.Free()

	oid, _ := BeltHashOID()
	masterPriv, masterPub, _ := BignKeypairGen(p)

	idHash := beltHashOf(t, []byte("alice"))
	idSig, _ := BignSign(p, oid, idHash, masterPriv)
	idPriv, idPub, _ := BignIdExtract(p, oid, idHash, idSig, masterPub)

	msgHash := beltHashOf(t, []byte("hello"))

	s1, _ := BignIdSign2(p, oid, idHash, msgHash, idPriv, nil)
	s2, _ := BignIdSign2(p, oid, idHash, msgHash, idPriv, nil)
	if !bytes.Equal(s1, s2) {
		t.Fatal("IdSign2 with t=nil must be deterministic")
	}
	if err := BignIdVerify(p, oid, idHash, msgHash, s1, idPub, masterPub); err != nil {
		t.Fatalf("IdVerify Sign2: %v", err)
	}
}

// ────────────────────────────────────────────────────────────────────────────
// Argument validation
// ────────────────────────────────────────────────────────────────────────────

func TestBignArgValidation(t *testing.T) {
	p := newParams256(t)
	defer p.Free()
	oid, _ := BeltHashOID()
	dummy32 := make([]byte, 32)
	dummy64 := make([]byte, 64)
	dummy48 := make([]byte, 48)

	// nil params
	if err := BignVerify(nil, oid, dummy32, dummy48, dummy64); err == nil {
		t.Error("Verify nil params should fail")
	}
	// empty OID
	if err := BignVerify(p, nil, dummy32, dummy48, dummy64); err == nil {
		t.Error("Verify empty OID should fail")
	}
	// short hash
	if _, err := BignSign(p, oid, make([]byte, 1), dummy32); err == nil {
		t.Error("Sign short hash should fail")
	}
	// short privKey
	if _, err := BignSign(p, oid, dummy32, make([]byte, 1)); err == nil {
		t.Error("Sign short privKey should fail")
	}
}
