package brng

import (
	"bytes"
	"errors"
	bee2 "github.com/miniusercoder/bee2go/v3"
	"testing"
)

func TestCTRReadZerosAndChunking(t *testing.T) {
	a, _ := NewCTR(make([]byte, 32), nil)
	defer a.Close()
	b, _ := NewCTR(make([]byte, 32), nil)
	defer b.Close()
	x := bytes.Repeat([]byte{42}, 97)
	y := make([]byte, 97)
	a.Read(x)
	b.Read(y[:1])
	b.Read(y[1:31])
	b.Read(y[31:])
	if !bytes.Equal(x, y) {
		t.Fatal("Read must generate from zero input independent of destination/chunking")
	}
	a.Close()
	a.Close()
	if _, e := a.Read(nil); !errors.Is(e, bee2.ErrClosed) {
		t.Fatal(e)
	}
}
func TestInvalidIV(t *testing.T) {
	if r, e := NewCTR(make([]byte, 32), make([]byte, 31)); e == nil {
		r.Close()
		t.Fatal("accepted short IV")
	}
}
func TestHMACOwnsLongIV(t *testing.T) {
	iv := bytes.Repeat([]byte{9}, 80)
	a, e := NewHMAC([]byte("key"), iv)
	if e != nil {
		t.Fatal(e)
	}
	defer a.Close()
	b, _ := NewHMAC([]byte("key"), append([]byte(nil), iv...))
	defer b.Close()
	clear(iv)
	x, y := make([]byte, 99), make([]byte, 99)
	a.Read(x)
	b.Read(y)
	if !bytes.Equal(x, y) {
		t.Fatal("IV was retained in Go memory")
	}
}
