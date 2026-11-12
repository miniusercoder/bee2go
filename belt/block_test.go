package belt

import (
	"bytes"
	"crypto/cipher"
	"encoding/hex"
	"testing"
)

func TestBlockKAT(t *testing.T) {
	key, _ := hex.DecodeString("e9dee72c8f0c0fa62ddb49f46f73964706075316ed247a3739cba38303a98bf6")
	src, _ := hex.DecodeString("b194bac80a08f53b366d008e584a5de4")
	want, _ := hex.DecodeString("69cca1c93557c9e3d66bc3e0fa88fa6e")
	b, e := NewBlock(key)
	if e != nil {
		t.Fatal(e)
	}
	defer b.Close()
	var _ cipher.Block = b
	got := make([]byte, 16)
	b.Encrypt(got, src)
	if !bytes.Equal(got, want) {
		t.Fatalf("got %x", got)
	}
	b.Decrypt(got, got)
	if !bytes.Equal(got, src) {
		t.Fatal("decrypt")
	}
}
