package bee2go

import "testing"

func TestMemWipe(t *testing.T) {
	buf := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF}

	MemWipe(buf)

	for i, b := range buf {
		if b != 0 {
			t.Fatalf("byte %d was not wiped: got 0x%02X", i, b)
		}
	}
}

func TestMemWipeOnlyTouchesSliceLength(t *testing.T) {
	const guard = byte(0xA5)
	backing := []byte{guard, 1, 2, 3, 4, guard}

	MemWipe(backing[1:5])

	if backing[0] != guard || backing[5] != guard {
		t.Fatalf("MemWipe modified data outside the slice: % X", backing)
	}
	for i, b := range backing[1:5] {
		if b != 0 {
			t.Fatalf("slice byte %d was not wiped: got 0x%02X", i, b)
		}
	}
}

func TestMemWipeEmpty(t *testing.T) {
	tests := []struct {
		name string
		buf  []byte
	}{
		{name: "nil", buf: nil},
		{name: "empty", buf: []byte{}},
		{name: "zero length with capacity", buf: make([]byte, 0, 8)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			MemWipe(tt.buf)
		})
	}
}

func TestMemWipeEmptyDoesNotTouchCapacity(t *testing.T) {
	backing := []byte{1, 2, 3, 4}

	MemWipe(backing[:0])

	want := []byte{1, 2, 3, 4}
	for i := range backing {
		if backing[i] != want[i] {
			t.Fatalf("byte %d behind an empty slice was modified: got %d, want %d", i, backing[i], want[i])
		}
	}
}
