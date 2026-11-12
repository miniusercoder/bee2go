package belt

import (
	"bytes"
	"errors"
	bee2 "github.com/miniusercoder/bee2go/v3"
	"testing"
)

func TestStreamingMAC(t *testing.T) {
	h := beltHBytes()
	for _, tc := range []struct {
		new func([]byte) (*MACState, error)
		one func([]byte, []byte) ([]byte, error)
	}{{NewMAC, MAC}, {NewHMAC, HMAC}} {
		m, e := tc.new(h[128:160])
		if e != nil {
			t.Fatal(e)
		}
		m.Write(h[:7])
		m.Write(h[7:48])
		want, e := tc.one(h[:48], h[128:160])
		if e != nil || !bytes.Equal(m.Sum(nil), want) || !bytes.Equal(m.Sum(nil), want) {
			t.Fatal("streaming", e)
		}
		m.Reset()
		m.Write(h[:48])
		if !bytes.Equal(m.Sum(nil), want) {
			t.Fatal("reset")
		}
		m.Close()
		if _, e = m.Write(nil); !errors.Is(e, bee2.ErrClosed) {
			t.Fatal(e)
		}
	}
}
