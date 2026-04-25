package bee2go

import (
	"bytes"
	"testing"
)

// ────────────────────────────────────────────────────────────────────────────
// BrngCTR
// ────────────────────────────────────────────────────────────────────────────

func TestBrngCTRRead(t *testing.T) {
	H := beltHBytes()
	key := H[128:160]
	iv := H[192:224]

	r, err := NewBrngCTR(key, iv)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Free()

	buf := make([]byte, 64)
	n, err := r.Read(buf)
	if err != nil || n != 64 {
		t.Fatalf("Read n=%d err=%v", n, err)
	}
	if bytes.Equal(buf, make([]byte, 64)) {
		t.Fatal("CTR output is all-zero")
	}
}

// Same key+IV must produce identical output (determinism).
func TestBrngCTRDeterministic(t *testing.T) {
	H := beltHBytes()
	key := H[128:160]
	iv := H[192:224]

	r1, _ := NewBrngCTR(key, iv)
	defer r1.Free()
	r2, _ := NewBrngCTR(key, iv)
	defer r2.Free()

	b1 := make([]byte, 96)
	b2 := make([]byte, 96)
	r1.Read(b1)
	r2.Read(b2)

	if !bytes.Equal(b1, b2) {
		t.Fatal("CTR: same key+IV produced different output")
	}
}

// Different IVs must produce different output.
func TestBrngCTRDifferentIV(t *testing.T) {
	H := beltHBytes()
	key := H[128:160]
	iv1 := H[192:224]
	iv2 := make([]byte, 32)
	copy(iv2, iv1)
	iv2[0] ^= 0xFF

	r1, _ := NewBrngCTR(key, iv1)
	defer r1.Free()
	r2, _ := NewBrngCTR(key, iv2)
	defer r2.Free()

	b1 := make([]byte, 32)
	b2 := make([]byte, 32)
	r1.Read(b1)
	r2.Read(b2)

	if bytes.Equal(b1, b2) {
		t.Fatal("CTR: different IVs produced same output")
	}
}

// IV() returns the updated synchronisation value (non-zero after reads).
func TestBrngCTRIV(t *testing.T) {
	H := beltHBytes()
	key := H[128:160]
	iv := H[192:224]

	r, _ := NewBrngCTR(key, iv)
	defer r.Free()

	buf := make([]byte, 64)
	r.Read(buf)

	updatedIV := r.IV()
	if len(updatedIV) != 32 {
		t.Fatalf("IV length=%d want 32", len(updatedIV))
	}
}

// BrngCTRRand high-level function must match streaming API output.
func TestBrngCTRRandMatchesStreaming(t *testing.T) {
	H := beltHBytes()
	key := H[128:160]
	iv := H[192:224]

	out1, _, err := BrngCTRRand(64, key, iv)
	if err != nil {
		t.Fatal(err)
	}

	r, _ := NewBrngCTR(key, iv)
	defer r.Free()
	out2 := make([]byte, 64)
	r.Read(out2)

	if !bytes.Equal(out1, out2) {
		t.Fatal("BrngCTRRand differs from streaming API")
	}
}

// BrngCTRRand must update the IV in-place.
func TestBrngCTRRandUpdatesIV(t *testing.T) {
	H := beltHBytes()
	key := H[128:160]
	iv := make([]byte, 32)
	copy(iv, H[192:224])

	originalIV := make([]byte, 32)
	copy(originalIV, iv)

	_, newIV, err := BrngCTRRand(32, key, iv)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(newIV, originalIV) {
		t.Fatal("BrngCTRRand did not update IV")
	}
}

// Wrong key length must be rejected.
func TestBrngCTRBadKey(t *testing.T) {
	if _, err := NewBrngCTR(make([]byte, 16), nil); err == nil {
		t.Error("16-byte key should be rejected (must be 32)")
	}
}

// ────────────────────────────────────────────────────────────────────────────
// BrngHMAC
// ────────────────────────────────────────────────────────────────────────────

func TestBrngHMACRead(t *testing.T) {
	H := beltHBytes()
	key := H[128:160]
	iv := H[192:224]

	r, err := NewBrngHMAC(key, iv)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Free()

	buf := make([]byte, 64)
	n, err := r.Read(buf)
	if err != nil || n != 64 {
		t.Fatalf("Read n=%d err=%v", n, err)
	}
	if bytes.Equal(buf, make([]byte, 64)) {
		t.Fatal("HMAC output is all-zero")
	}
}

// Same key+IV must produce identical output.
func TestBrngHMACDeterministic(t *testing.T) {
	H := beltHBytes()
	key := H[128:160]
	iv := H[0:16]

	r1, _ := NewBrngHMAC(key, iv)
	defer r1.Free()
	r2, _ := NewBrngHMAC(key, iv)
	defer r2.Free()

	b1 := make([]byte, 64)
	b2 := make([]byte, 64)
	r1.Read(b1)
	r2.Read(b2)

	if !bytes.Equal(b1, b2) {
		t.Fatal("HMAC: same key+IV produced different output")
	}
}

// Different keys must produce different output.
func TestBrngHMACDifferentKeys(t *testing.T) {
	H := beltHBytes()
	iv := H[192:224]

	r1, _ := NewBrngHMAC(H[128:160], iv)
	defer r1.Free()
	r2, _ := NewBrngHMAC(H[0:32], iv)
	defer r2.Free()

	b1 := make([]byte, 32)
	b2 := make([]byte, 32)
	r1.Read(b1)
	r2.Read(b2)

	if bytes.Equal(b1, b2) {
		t.Fatal("HMAC: different keys produced same output")
	}
}

// BrngHMACRand high-level function must match streaming API.
func TestBrngHMACRandMatchesStreaming(t *testing.T) {
	H := beltHBytes()
	key := H[128:160]
	iv := H[0:32]

	out1, err := BrngHMACRand(64, key, iv)
	if err != nil {
		t.Fatal(err)
	}

	r, _ := NewBrngHMAC(key, iv)
	defer r.Free()
	out2 := make([]byte, 64)
	r.Read(out2)

	if !bytes.Equal(out1, out2) {
		t.Fatal("BrngHMACRand differs from streaming API")
	}
}

// Empty key must be rejected.
func TestBrngHMACEmptyKey(t *testing.T) {
	if _, err := NewBrngHMAC(nil, nil); err == nil {
		t.Error("empty key should be rejected")
	}
	if _, err := BrngHMACRand(32, nil, nil); err == nil {
		t.Error("empty key should be rejected")
	}
}
