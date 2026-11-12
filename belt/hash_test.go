package belt

import (
	"bytes"
	"encoding/hex"
	"errors"
	bee2 "github.com/miniusercoder/bee2go/v3"
	"testing"
)

func TestHashKATAndLifecycle(t *testing.T) {
	src, _ := hex.DecodeString("b194bac80a08f53b366d008e58")
	want, _ := hex.DecodeString("abef9725d4c5a83597a367d14494cc2542f20f659ddfecc961a3ec550cba8c75")
	h, e := NewHash()
	if e != nil {
		t.Fatal(e)
	}
	h.Write(src)
	if !bytes.Equal(h.Sum(nil), want) || !bytes.Equal(h.Sum(nil), want) {
		t.Fatal("KAT or Sum")
	}
	h.Reset()
	h.Write(src)
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
	h, e := NewHash()
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
