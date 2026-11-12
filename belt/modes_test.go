package belt

import (
	"bytes"
	"encoding/hex"
	"errors"
	bee2 "github.com/miniusercoder/bee2go/v3"
	"testing"
)

func TestECBKAT(t *testing.T) {
	key, _ := hex.DecodeString("e9dee72c8f0c0fa62ddb49f46f73964706075316ed247a3739cba38303a98bf6")
	src, _ := hex.DecodeString("b194bac80a08f53b366d008e584a5de4")
	want, _ := hex.DecodeString("69cca1c93557c9e3d66bc3e0fa88fa6e")
	got, e := ECBEncrypt(src, key)
	if e != nil || !bytes.Equal(got, want) {
		t.Fatalf("%x %v", got, e)
	}
	got, e = ECBDecrypt(got, key)
	if e != nil || !bytes.Equal(got, src) {
		t.Fatal("decrypt", e)
	}
}
func TestTamperReturnsNoPlaintext(t *testing.T) {
	key, iv := make([]byte, 32), make([]byte, 16)
	ct, tag, e := DWPWrap([]byte("message"), []byte("aad"), key, iv)
	if e != nil {
		t.Fatal(e)
	}
	tag[0] ^= 1
	got, e := DWPUnwrap(ct, []byte("aad"), tag, key, iv)
	if got != nil || !errors.Is(e, bee2.ErrAuthentication) {
		t.Fatalf("%x %v", got, e)
	}
}
func TestAEADKATAndTamper(t *testing.T) {
	h := beltHBytes()
	for _, tc := range []struct {
		n       int
		wrap    func([]byte, []byte, []byte, []byte) ([]byte, []byte, error)
		unwrap  func([]byte, []byte, []byte, []byte, []byte) ([]byte, error)
		ct, tag string
	}{{16, DWPWrap, DWPUnwrap, "52c9af96ff50f64435fc43def56bd797", "3b2e0aeb2b91854b"}, {15, CHEWrap, CHEUnwrap, "bf3daeaf5d18d2bcc30ea62d2e70a4", "548622b844123ff7"}} {
		ct, tag, e := tc.wrap(h[:tc.n], h[16:48], h[128:160], h[192:208])
		wct, _ := hex.DecodeString(tc.ct)
		wt, _ := hex.DecodeString(tc.tag)
		if e != nil || !bytes.Equal(ct, wct) || !bytes.Equal(tag, wt) {
			t.Fatalf("%x %x %v", ct, tag, e)
		}
		for i := 0; i < 3; i++ {
			c, a, m := bytes.Clone(ct), bytes.Clone(h[16:48]), bytes.Clone(tag)
			switch i {
			case 0:
				c[0] ^= 1
			case 1:
				a[0] ^= 1
			case 2:
				m[0] ^= 1
			}
			p, e := tc.unwrap(c, a, m, h[128:160], h[192:208])
			if p != nil || !errors.Is(e, bee2.ErrAuthentication) {
				t.Fatalf("tamper %d: %x %v", i, p, e)
			}
		}
	}
}
