package rng

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	bee2 "github.com/miniusercoder/bee2go/v3"
	"testing"
)

func TestOwners(t *testing.T) {
	a, e := New()
	if e != nil {
		t.Fatal(e)
	}
	defer a.Close()
	b, e := New()
	if e != nil {
		t.Fatal(e)
	}
	defer b.Close()
	a.Close()
	a.Close()
	if _, e = a.Read(nil); !errors.Is(e, bee2.ErrClosed) {
		t.Fatal(e)
	}
	out := make([]byte, 32)
	if n, e := b.Read(out); e != nil || n != 32 {
		t.Fatal(n, e)
	}
	if e = b.Rekey(); e != nil {
		t.Fatal(e)
	}
}
func TestEntropy(t *testing.T) {
	b := make([]byte, 32)
	n, e := ReadEntropy(b, "sys")
	if e != nil || n != 32 {
		t.Fatal(n, e)
	}
	if _, e = ReadEntropy(b, "unknown"); e == nil {
		t.Fatal("accepted unknown source")
	}
	if TestFIPS1(make([]byte, 2499)) {
		t.Fatal("short FIPS sample")
	}
}
func TestAdditionalEntropySource(t *testing.T) {
	if g, e := NewWithSource(bytes.NewReader(make([]byte, 31))); g != nil || !errors.Is(e, bee2.ErrRandom) {
		t.Fatal("short source", e)
	}
	a, e := NewWithSource(bytes.NewReader(make([]byte, 32)))
	if e != nil {
		t.Fatal(e)
	}
	b, e := NewWithSource(bytes.NewReader(bytes.Repeat([]byte{1}, 32)))
	if e != nil {
		t.Fatal(e)
	}
	a.Close()
	if !IsCreated() {
		t.Fatal("second owner lost global state")
	}
	b.Close()
	if IsCreated() {
		t.Fatal("last owner did not release state")
	}
}
func TestFIPSDiagnostics(t *testing.T) {
	for _, f := range []func([]byte) bool{TestFIPS1, TestFIPS2, TestFIPS3, TestFIPS4} {
		if f(make([]byte, 2500)) || f(make([]byte, 2499)) {
			t.Fatal("constant/short sample passed")
		}
	}
	if e := TestSource("absent-source"); e == nil {
		t.Fatal("unknown source")
	}
}
func TestFIPSPositiveSampleAndHealth(t *testing.T) {
	// Independent deterministic sample: SHA-256 of LE64 counters 0..78, first2500 bytes.
	var sample []byte
	for n := uint64(0); len(sample) < 2500; n++ {
		var input [8]byte
		binary.LittleEndian.PutUint64(input[:], n)
		sum := sha256.Sum256(input[:])
		sample = append(sample, sum[:]...)
	}
	for i, f := range []func([]byte) bool{TestFIPS1, TestFIPS2, TestFIPS3, TestFIPS4} {
		if !f(sample[:2500]) {
			t.Fatalf("positive sample FIPS%d", i+1)
		}
	}
	// Health depends on actual hardware and available sources. Every outcome must
	// be either success or the documented entropy category, never fabricated data.
	for _, f := range []func() error{Health, Health2} {
		if e := f(); e != nil && !errors.Is(e, bee2.ErrRandom) {
			t.Fatal(e)
		}
	}
}
