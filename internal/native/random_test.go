package native

import (
	"bytes"
	"errors"
	bee2 "github.com/miniusercoder/bee2go/v3"
	"io"
	"testing"
)

func TestEntropyFailureBeforeNative(t *testing.T) {
	for _, r := range []io.Reader{bytes.NewReader(nil), bytes.NewReader(make([]byte, 63))} {
		s, e := NewRandom(r)
		if s != nil || !errors.Is(e, bee2.ErrRandom) {
			t.Fatalf("got %v %v", s, e)
		}
	}
}
func TestRandomClose(t *testing.T) {
	s, e := NewRandom(bytes.NewReader(make([]byte, 64)))
	if e != nil {
		t.Fatal(e)
	}
	s.Close()
	s.Close()
	if _, e = s.Read(make([]byte, 1)); !errors.Is(e, bee2.ErrClosed) {
		t.Fatal(e)
	}
}
