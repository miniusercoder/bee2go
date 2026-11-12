package bash

import (
	"bytes"
	"encoding/hex"
	"errors"
	bee2 "github.com/miniusercoder/bee2go/v3"
	"testing"
)

func TestHashKATAndLifecycle(t *testing.T) {
	want, _ := hex.DecodeString("114C3DFAE373D9BCBC3602D6386F2D6A2059BA1BF9048DBAA5146A6CB775709D")
	h, e := NewHash(128)
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(h.Sum(nil), want) || !bytes.Equal(h.Sum(nil), want) {
		t.Fatal("empty KAT or Sum")
	}
	h.Write([]byte("x"))
	h.Reset()
	if !bytes.Equal(h.Sum(nil), want) {
		t.Fatal("Reset")
	}
	h.Close()
	h.Close()
	if _, e = h.Write(nil); !errors.Is(e, bee2.ErrClosed) {
		t.Fatalf("closed: %v", e)
	}
}
func TestClosedHashMethodsPanic(t *testing.T) {
	h, e := NewHash(128)
	if e != nil {
		t.Fatal(e)
	}
	h.Close()
	for name, fn := range map[string]func(){"size": func() { h.Size() }, "blocksize": func() { h.BlockSize() }, "sum": func() { h.Sum(nil) }, "reset": h.Reset} {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatal("expected panic")
				}
			}()
			fn()
		})
	}
}
func TestAllHashLevels(t *testing.T) {
	for l := 16; l <= 256; l += 16 {
		h, e := NewHash(l)
		if e != nil {
			t.Fatalf("%d %v", l, e)
		}
		if h.Size() != l/4 || h.BlockSize() != 192-l/2 {
			t.Fatal(l)
		}
		h.Write([]byte("message"))
		got := h.Sum(nil)
		h.Reset()
		h.Write([]byte("message"))
		if !bytes.Equal(got, h.Sum(nil)) {
			t.Fatal(l)
		}
		h.Close()
	}
	for _, l := range []int{-16, 0, 1, 15, 17, 257, 272} {
		if _, e := NewHash(l); !errors.Is(e, bee2.ErrInvalidInput) {
			t.Fatal(l, e)
		}
	}
}
