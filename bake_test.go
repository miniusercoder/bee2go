package bee2go

import (
	"bytes"
	"testing"
)

// ────────────────────────────────────────────────────────────────────────────
// BSTS protocol round-trip
// ────────────────────────────────────────────────────────────────────────────

// TestBakeBSTSRoundTrip runs the full 3-message BSTS handshake between two
// parties (A and B) and asserts that both derive the same 32-byte session key.
//
// Certificate format used throughout: <identity_bytes> || <pubkey_bytes>.
// BakeAcceptAllCertVal extracts the last l/2 bytes as the public key.
func TestBakeBSTSRoundTrip(t *testing.T) {
	params, err := NewBignParams256v1()
	if err != nil {
		t.Fatal(err)
	}
	defer params.Free()

	// Generate independent keypairs for A and B.
	privA, pubA, err := BignKeypairGen(params)
	if err != nil {
		t.Fatal("keygen A:", err)
	}
	privB, pubB, err := BignKeypairGen(params)
	if err != nil {
		t.Fatal("keygen B:", err)
	}

	// Build certificates: identity prefix + public key (pubkey at the tail so
	// accept_all_certval can extract it as data[len-64:len]).
	certDataA := append([]byte("Alice"), pubA...)
	certDataB := append([]byte("Bob"), pubB...)

	valFn := BakeAcceptAllCertVal()
	rngFn := BakeDefaultRNG()

	certA, err := NewBakeCert(certDataA, valFn)
	if err != nil {
		t.Fatal("NewBakeCert A:", err)
	}
	defer certA.Free()

	certB, err := NewBakeCert(certDataB, valFn)
	if err != nil {
		t.Fatal("NewBakeCert B:", err)
	}
	defer certB.Free()

	settingsA, err := NewBakeSettings(true, true, nil, nil, rngFn, nil)
	if err != nil {
		t.Fatal("NewBakeSettings A:", err)
	}
	defer settingsA.Free()

	settingsB, err := NewBakeSettings(true, true, nil, nil, rngFn, nil)
	if err != nil {
		t.Fatal("NewBakeSettings B:", err)
	}
	defer settingsB.Free()

	stA, err := NewBakeBSTS(128, params, settingsA, privA, certA)
	if err != nil {
		t.Fatal("NewBakeBSTS A:", err)
	}
	defer stA.Free()

	stB, err := NewBakeBSTS(128, params, settingsB, privB, certB)
	if err != nil {
		t.Fatal("NewBakeBSTS B:", err)
	}
	defer stB.Free()

	// ── Protocol flow ──────────────────────────────────────────────────────
	//   B → A: M1  (B's ephemeral point)
	//   A → B: M2  (A's ephemeral point + A's cert + A's key confirm)
	//   B → A: M3  (B's cert + B's key confirm, validates A's cert)
	//   A:          validates B's cert (Step5)

	m1, err := stB.Step2()
	if err != nil {
		t.Fatal("Step2:", err)
	}

	m2, err := stA.Step3(m1)
	if err != nil {
		t.Fatal("Step3:", err)
	}

	m3, err := stB.Step4(m2, valFn)
	if err != nil {
		t.Fatal("Step4:", err)
	}

	if err := stA.Step5(m3, valFn); err != nil {
		t.Fatal("Step5:", err)
	}

	keyA, err := stA.StepG()
	if err != nil {
		t.Fatal("StepG A:", err)
	}
	keyB, err := stB.StepG()
	if err != nil {
		t.Fatal("StepG B:", err)
	}

	if !bytes.Equal(keyA, keyB) {
		t.Fatalf("session keys differ:\nA: %X\nB: %X", keyA, keyB)
	}
	if bytes.Equal(keyA, make([]byte, 32)) {
		t.Fatal("session key is all zeros")
	}
}

// BSTS mandates kca=true AND kcb=true; weaker settings must be rejected at
// initialisation time.
func TestBakeBSTSRequiresKeyConfirmation(t *testing.T) {
	params, _ := NewBignParams256v1()
	defer params.Free()

	_, pubA, _ := BignKeypairGen(params)
	valFn := BakeAcceptAllCertVal()
	rngFn := BakeDefaultRNG()

	certA, _ := NewBakeCert(append([]byte("A"), pubA...), valFn)
	defer certA.Free()

	for _, kc := range [][2]bool{{false, false}, {true, false}, {false, true}} {
		s, _ := NewBakeSettings(kc[0], kc[1], nil, nil, rngFn, nil)
		if s != nil {
			defer s.Free()
		}
		privA, _, _ := BignKeypairGen(params)
		_, err := NewBakeBSTS(128, params, s, privA, certA)
		if err == nil {
			t.Errorf("kca=%v kcb=%v should be rejected by BSTS", kc[0], kc[1])
		}
	}
}

// Two independent sessions must produce different session keys (random
// ephemeral values ensure this almost certainly).
func TestBakeBSTSSessionKeysAreRandom(t *testing.T) {
	params, _ := NewBignParams256v1()
	defer params.Free()

	runSession := func() []byte {
		privA, pubA, _ := BignKeypairGen(params)
		privB, pubB, _ := BignKeypairGen(params)

		valFn := BakeAcceptAllCertVal()
		rngFn := BakeDefaultRNG()

		certA, _ := NewBakeCert(append([]byte("A"), pubA...), valFn)
		defer certA.Free()
		certB, _ := NewBakeCert(append([]byte("B"), pubB...), valFn)
		defer certB.Free()

		sA, _ := NewBakeSettings(true, true, nil, nil, rngFn, nil)
		defer sA.Free()
		sB, _ := NewBakeSettings(true, true, nil, nil, rngFn, nil)
		defer sB.Free()

		stA, _ := NewBakeBSTS(128, params, sA, privA, certA)
		defer stA.Free()
		stB, _ := NewBakeBSTS(128, params, sB, privB, certB)
		defer stB.Free()

		m1, _ := stB.Step2()
		m2, _ := stA.Step3(m1)
		m3, _ := stB.Step4(m2, valFn)
		_ = stA.Step5(m3, valFn)

		key, _ := stA.StepG()
		return key
	}

	k1 := runSession()
	k2 := runSession()
	if bytes.Equal(k1, k2) {
		t.Fatal("two independent sessions produced the same session key")
	}
}

// ────────────────────────────────────────────────────────────────────────────
// Argument validation
// ────────────────────────────────────────────────────────────────────────────

func TestBakeBSTSNilParams(t *testing.T) {
	params, _ := NewBignParams256v1()
	defer params.Free()

	valFn := BakeAcceptAllCertVal()
	rngFn := BakeDefaultRNG()

	certA, _ := NewBakeCert(make([]byte, 68), valFn)
	defer certA.Free()
	s, _ := NewBakeSettings(true, true, nil, nil, rngFn, nil)
	defer s.Free()

	if _, err := NewBakeBSTS(128, nil, s, make([]byte, 32), certA); err == nil {
		t.Error("nil params should be rejected")
	}
	if _, err := NewBakeBSTS(128, params, nil, make([]byte, 32), certA); err == nil {
		t.Error("nil settings should be rejected")
	}
	if _, err := NewBakeBSTS(128, params, s, make([]byte, 32), nil); err == nil {
		t.Error("nil cert should be rejected")
	}
}

// ────────────────────────────────────────────────────────────────────────────
// BakeAcceptAllCertVal and BakeDefaultRNG are non-nil
// ────────────────────────────────────────────────────────────────────────────

func TestBakeHelperPtrsNonNil(t *testing.T) {
	if BakeDefaultRNG() == nil {
		t.Error("BakeDefaultRNG returned nil")
	}
	if BakeAcceptAllCertVal() == nil {
		t.Error("BakeAcceptAllCertVal returned nil")
	}
}
