package bee2go

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// mustHex decodes a compact hex string; fatal on bad input.
func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

// ────────────────────────────────────────────────────────────────────────────
// bash-hash KAT (STB 34.101.77 appendix A.3)
// ────────────────────────────────────────────────────────────────────────────

func TestBashHashKAT(t *testing.T) {
	H := beltHBytes()

	tests := []struct {
		l    int
		n    int
		want string
	}{
		// A.3.1 – A.3.4  bash256 (l=128)
		{128, 0, "114C3DFAE373D9BCBC3602D6386F2D6A2059BA1BF9048DBAA5146A6CB775709D"},
		{128, 127, "3D7F4EFA00E9BA33FEED259986567DCF5C6D12D51057A968F14F06CC0F905961"},
		{128, 128, "D7F428311254B8B2D00F7F9EEFBD8F3025FA87C4BABD1BDDBE87E35B7AC80DD6"},
		{128, 135, "1393FA1B65172F2D18946AEAE576FA1CF54FDD354A0CB2974A997DC4865D3100"},
		// A.3.5 – A.3.7  bash384 (l=192)
		{192, 95,
			"64334AF830D33F63E9ACDFA184E32522" +
				"103FFF5C6860110A2CD369EDBC04387C" +
				"501D8F92F749AE4DE15A8305C353D64D"},
		{192, 96,
			"D06EFBC16FD6C0880CBFC6A4E3D65AB1" +
				"01FA82826934190FAABEBFBFFEDE93B2" +
				"2B85EA72A7FB3147A133A5A8FEBD8320"},
		{192, 108,
			"FF763296571E2377E71A1538070CC0DE" +
				"88888606F32EEE6B082788D246686B00" +
				"FC05A17405C5517699DA44B7EF5F55AB"},
		// A.3.8 – A.3.11  bash512 (l=256)
		{256, 63,
			"2A66C87C189C12E255239406123BDEDB" +
				"F19955EAF0808B2AD705E249220845E2" +
				"0F4786FB6765D0B5C48984B1B16556EF" +
				"19EA8192B985E4233D9C09508D6339E7"},
		{256, 64,
			"07ABBF8580E7E5A321E9B940F667AE20" +
				"9E2952CEF557978AE743DB086BAB4885" +
				"B708233C3F5541DF8AAFC3611482FDE4" +
				"98E58B3379A6622DAC2664C9C118A162"},
		{256, 127,
			"526073918F97928E9D15508385F42F03" +
				"ADE3211A23900A30131F8A1E3E1EE21C" +
				"C09D13CFF6981101235D895746A4643F" +
				"0AA62B0A7BC98A269E4507A257F0D4EE"},
		{256, 192,
			"8724C7FF8A2A83F22E38CB9763777B96" +
				"A70ABA3444F214C763D93CD6D19FCFDE" +
				"6C3D3931857C4FF6CCCD49BD99852FE9" +
				"EAA7495ECCDD96B571E0EDCF47F89768"},
	}

	for _, tc := range tests {
		got, err := BashHash(tc.l, H[:tc.n])
		if err != nil {
			t.Errorf("l=%d n=%d: %v", tc.l, tc.n, err)
			continue
		}
		want := mustHex(t, tc.want)
		if !bytes.Equal(got, want) {
			t.Errorf("l=%d n=%d:\ngot  %X\nwant %X", tc.l, tc.n, got, want)
		}
	}
}

// ────────────────────────────────────────────────────────────────────────────
// hash.Hash interface compliance
// ────────────────────────────────────────────────────────────────────────────

func TestBashHashInterface(t *testing.T) {
	H := beltHBytes()
	for _, l := range []int{128, 192, 256} {
		h, err := NewBashHash(l)
		if err != nil {
			t.Fatalf("l=%d NewBashHash: %v", l, err)
		}
		bh := h.(*bashHash)
		defer bh.Free()

		if h.Size() != l/4 {
			t.Errorf("l=%d Size()=%d want %d", l, h.Size(), l/4)
		}
		if want := (1536 - 2*l) / 8; h.BlockSize() != want {
			t.Errorf("l=%d BlockSize()=%d want %d", l, h.BlockSize(), want)
		}

		_, _ = h.Write(H[:64])
		s1 := h.Sum(nil)
		s2 := h.Sum(nil) // Sum must not consume state
		if !bytes.Equal(s1, s2) {
			t.Errorf("l=%d Sum is not idempotent", l)
		}
		if len(s1) != l/4 {
			t.Errorf("l=%d Sum length=%d want %d", l, len(s1), l/4)
		}

		// Reset and re-hash must match single-call BashHash.
		h.Reset()
		_, _ = h.Write(H[:64])
		ref, _ := BashHash(l, H[:64])
		if !bytes.Equal(h.Sum(nil), ref) {
			t.Errorf("l=%d Reset+Re-hash mismatch", l)
		}
	}
}

// ────────────────────────────────────────────────────────────────────────────
// Incremental write must match single-call
// ────────────────────────────────────────────────────────────────────────────

func TestBashHashIncremental(t *testing.T) {
	H := beltHBytes()
	for _, l := range []int{128, 192, 256} {
		ref, _ := BashHash(l, H[:100])
		h, _ := NewBashHash(l)
		bh := h.(*bashHash)
		defer bh.Free()

		for i := 0; i < 100; {
			chunk := 7
			if i+chunk > 100 {
				chunk = 100 - i
			}
			h.Write(H[i : i+chunk])
			i += chunk
		}
		if !bytes.Equal(h.Sum(nil), ref) {
			t.Errorf("l=%d incremental mismatch", l)
		}
	}
}

// ────────────────────────────────────────────────────────────────────────────
// Invalid security level must be rejected
// ────────────────────────────────────────────────────────────────────────────

func TestBashHashInvalidLevel(t *testing.T) {
	for _, bad := range []int{0, 64, 100, 512} {
		if _, err := NewBashHash(bad); err == nil {
			t.Errorf("NewBashHash(%d) should fail", bad)
		}
		if _, err := BashHash(bad, []byte("test")); err == nil {
			t.Errorf("BashHash(%d, ...) should fail", bad)
		}
	}
}

// ────────────────────────────────────────────────────────────────────────────
// BashPrg: encrypt / decrypt round-trip
// ────────────────────────────────────────────────────────────────────────────

func TestBashPrgEncryptDecrypt(t *testing.T) {
	H := beltHBytes()
	key := H[128:144]
	ann := H[0:4]

	prg, err := NewBashPrg(128, 1, ann, key)
	if err != nil {
		t.Fatalf("NewBashPrg: %v", err)
	}
	defer prg.Free()

	plain := []byte("hello, bee2 world! stream cipher test message.")
	ct := make([]byte, len(plain))
	copy(ct, plain)
	prg.Encrypt(ct)

	if bytes.Equal(ct, plain) {
		t.Fatal("Encrypt did not change plaintext")
	}

	prg2, _ := NewBashPrg(128, 1, ann, key)
	defer prg2.Free()
	prg2.Decrypt(ct)

	if !bytes.Equal(ct, plain) {
		t.Fatal("Decrypt did not recover plaintext")
	}
}

// ────────────────────────────────────────────────────────────────────────────
// BashPrg: Squeeze is deterministic
// ────────────────────────────────────────────────────────────────────────────

func TestBashPrgSqueezeDeterministic(t *testing.T) {
	H := beltHBytes()
	key := H[128:160]

	p1, _ := NewBashPrg(256, 1, nil, key)
	defer p1.Free()
	out1 := p1.Squeeze(64)

	p2, _ := NewBashPrg(256, 1, nil, key)
	defer p2.Free()
	out2 := p2.Squeeze(64)

	if !bytes.Equal(out1, out2) {
		t.Fatal("Squeeze not deterministic for same key")
	}
}

// ────────────────────────────────────────────────────────────────────────────
// BashPrg: unkeyed Absorb + Squeeze is non-zero
// ────────────────────────────────────────────────────────────────────────────

func TestBashPrgAbsorbSqueeze(t *testing.T) {
	prg, err := NewBashPrg(128, 2, nil, nil)
	if err != nil {
		t.Fatalf("NewBashPrg unkeyed: %v", err)
	}
	defer prg.Free()

	prg.Absorb(beltHBytes()[:127])
	out := prg.Squeeze(32)

	if bytes.Equal(out, make([]byte, 32)) {
		t.Fatal("Squeeze returned all-zero output after Absorb")
	}
}

// ────────────────────────────────────────────────────────────────────────────
// BashPrg: Ratchet changes future output
// ────────────────────────────────────────────────────────────────────────────

func TestBashPrgRatchet(t *testing.T) {
	H := beltHBytes()
	key := H[128:160]

	p1, _ := NewBashPrg(256, 1, nil, key)
	defer p1.Free()
	before := p1.Squeeze(32)

	p2, _ := NewBashPrg(256, 1, nil, key)
	defer p2.Free()
	p2.Ratchet()
	after := p2.Squeeze(32)

	if bytes.Equal(before, after) {
		t.Fatal("Ratchet did not change output")
	}
}

// ────────────────────────────────────────────────────────────────────────────
// BashPrg: Restart is deterministic — two automata in the same state produce
// identical output after identical Restart calls. (Restart XORs new key
// material into the current state; it does not reset to the initial state.)
// ────────────────────────────────────────────────────────────────────────────

func TestBashPrgRestart(t *testing.T) {
	H := beltHBytes()
	key := H[128:144]
	ann := H[0:4]
	newAnn := H[4:8]

	// Two automata in the same initial state.
	p1, _ := NewBashPrg(128, 1, ann, key)
	defer p1.Free()
	p2, _ := NewBashPrg(128, 1, ann, key)
	defer p2.Free()

	// Advance both identically so they share the same mid-session state.
	p1.Squeeze(16)
	p2.Squeeze(16)

	// Restart both with the same new announcement.
	p1.Restart(newAnn, nil)
	p2.Restart(newAnn, nil)

	// Identical Restart on identical states must yield identical future output.
	out1 := p1.Squeeze(32)
	out2 := p2.Squeeze(32)
	if !bytes.Equal(out1, out2) {
		t.Fatal("Restart: two instances diverged after identical Restart")
	}
	if bytes.Equal(out1, make([]byte, 32)) {
		t.Fatal("Restart: output is all zeros")
	}
}

// ────────────────────────────────────────────────────────────────────────────
// BashPrg: invalid parameter rejection
// ────────────────────────────────────────────────────────────────────────────

func TestBashPrgInvalidParams(t *testing.T) {
	if _, err := NewBashPrg(64, 1, nil, nil); err == nil {
		t.Error("l=64 should be rejected")
	}
	if _, err := NewBashPrg(128, 3, nil, nil); err == nil {
		t.Error("d=3 should be rejected")
	}
}
