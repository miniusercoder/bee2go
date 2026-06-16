package bee2go

import (
	"bytes"
	"errors"
	"testing"
)

// ────────────────────────────────────────────────────────────────────────────
// FIPS statistical tests
//
// The assertions on hand-picked data mirror bee2's own rng_test.c.
// ────────────────────────────────────────────────────────────────────────────

// All bytes 0x5C (0101 1100, four ones per byte → 10000 ones total):
// FIPS1 passes, FIPS2 and FIPS3 fail, FIPS4 passes.
func TestRngTestFIPSConstByte(t *testing.T) {
	buf := bytes.Repeat([]byte{0x5C}, 2500)

	if !RngTestFIPS1(buf) {
		t.Error("FIPS1 should pass for 0x5C-filled buffer")
	}
	if RngTestFIPS2(buf) {
		t.Error("FIPS2 should fail for 0x5C-filled buffer")
	}
	if RngTestFIPS3(buf) {
		t.Error("FIPS3 should fail for 0x5C-filled buffer")
	}
	if !RngTestFIPS4(buf) {
		t.Error("FIPS4 should pass for 0x5C-filled buffer")
	}
}

// Punching 69 zero bytes into the 0x5C buffer makes every test fail:
// the one-count drops below 9725 (FIPS1) and a long zero-run appears (FIPS4).
func TestRngTestFIPSWithZeroHole(t *testing.T) {
	buf := bytes.Repeat([]byte{0x5C}, 2500)
	for i := 10; i < 10+69; i++ {
		buf[i] = 0x00
	}

	if RngTestFIPS1(buf) {
		t.Error("FIPS1 should fail")
	}
	if RngTestFIPS2(buf) {
		t.Error("FIPS2 should fail")
	}
	if RngTestFIPS3(buf) {
		t.Error("FIPS3 should fail")
	}
	if RngTestFIPS4(buf) {
		t.Error("FIPS4 should fail")
	}
}

// A buffer shorter than 2500 bytes must never pass (no out-of-bounds read).
func TestRngTestFIPSShortBuffer(t *testing.T) {
	short := make([]byte, 100)
	if RngTestFIPS1(short) || RngTestFIPS2(short) ||
		RngTestFIPS3(short) || RngTestFIPS4(short) {
		t.Error("short buffer must not pass any FIPS test")
	}
}

// ────────────────────────────────────────────────────────────────────────────
// Entropy sources
// ────────────────────────────────────────────────────────────────────────────

// The OS source ("sys") is expected to be available and deliver a full request.
func TestRngESReadSys(t *testing.T) {
	buf := make([]byte, 32)
	n, err := RngESRead(buf, "sys")
	if err != nil {
		t.Fatalf("RngESRead(sys): %v", err)
	}
	if n != len(buf) {
		t.Fatalf("RngESRead(sys) returned %d octets, want %d", n, len(buf))
	}
	if bytes.Equal(buf, make([]byte, 32)) {
		t.Error("sys source returned all-zero data")
	}
}

// A zero-length request probes for the source without reading data.
func TestRngESReadProbe(t *testing.T) {
	n, err := RngESRead(nil, "sys")
	if err != nil {
		t.Fatalf("probing sys source: %v", err)
	}
	if n != 0 {
		t.Errorf("probe returned %d octets, want 0", n)
	}
}

// An unknown source name must report an error rather than succeed silently.
func TestRngESReadUnknownSource(t *testing.T) {
	if _, err := RngESRead(make([]byte, 16), "no-such-source"); err == nil {
		t.Error("unknown source should return an error")
	}
}

// RngESHealth depends on the host; it must return either success or one of the
// documented sentinel errors (never an opaque failure).
func TestRngESHealth(t *testing.T) {
	if err := RngESHealth(); err != nil {
		if !errors.Is(err, ErrNotEnoughEntropy) && !errors.Is(err, ErrBadEntropy) {
			t.Errorf("unexpected health error: %v", err)
		}
		t.Logf("RngESHealth: %v (environment-dependent)", err)
	}
}

// ────────────────────────────────────────────────────────────────────────────
// Generator
// ────────────────────────────────────────────────────────────────────────────

func TestRngGeneratorLifecycle(t *testing.T) {
	if RngIsValid() {
		t.Fatal("generator should be invalid before RngCreate")
	}
	if err := RngCreate(); err != nil {
		if errors.Is(err, ErrNotEnoughEntropy) {
			t.Skipf("not enough entropy in this environment: %v", err)
		}
		t.Fatalf("RngCreate: %v", err)
	}
	defer RngClose()

	if !RngIsValid() {
		t.Fatal("generator should be valid after RngCreate")
	}

	buf := make([]byte, 2500)
	RngStepR(buf)
	if bytes.Equal(buf, make([]byte, 2500)) {
		t.Fatal("RngStepR produced all-zero output")
	}
	if !RngTestFIPS1(buf) {
		t.Error("RngStepR output failed FIPS1 monobit test")
	}

	RngRekey()

	buf2 := make([]byte, 2500)
	RngStepR2(buf2)
	if bytes.Equal(buf2, make([]byte, 2500)) {
		t.Fatal("RngStepR2 produced all-zero output")
	}
	if bytes.Equal(buf, buf2) {
		t.Error("RngStepR and RngStepR2 produced identical output")
	}
}

// RngCreate is reference-counted: two creates require two closes before the
// generator becomes invalid.
func TestRngGeneratorRefCount(t *testing.T) {
	if err := RngCreate(); err != nil {
		if errors.Is(err, ErrNotEnoughEntropy) {
			t.Skipf("not enough entropy in this environment: %v", err)
		}
		t.Fatalf("RngCreate #1: %v", err)
	}
	if err := RngCreate(); err != nil {
		RngClose()
		t.Fatalf("RngCreate #2: %v", err)
	}

	RngClose()
	if !RngIsValid() {
		t.Error("generator should still be valid after one of two closes")
	}
	RngClose()
	if RngIsValid() {
		t.Error("generator should be invalid after balancing all creates")
	}
}

// The gen_i pointers used to bridge into bake/bign must be non-nil.
func TestRngGenPointers(t *testing.T) {
	if RngStepRGen() == nil {
		t.Error("RngStepRGen returned nil")
	}
	if RngStepR2Gen() == nil {
		t.Error("RngStepR2Gen returned nil")
	}
}
