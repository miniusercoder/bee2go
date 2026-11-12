package belt

import (
	"bytes"
	"encoding/hex"
	"reflect"
	"testing"
)

func TestDiskAndFMTKAT(t *testing.T) {
	h := beltHBytes()
	for _, tc := range []struct {
		name     string
		enc, dec func([]byte, []byte, []byte) ([]byte, error)
		want     string
	}{{"BDE", BDEEncrypt, BDEDecrypt, "e9cab32d879cc50c10378eb07c10f26307257e2dbe2b854cbc9f38282d59d6a77f952001c5d1244f53210a27c216d4bb"}, {"SDE", SDEEncrypt, SDEDecrypt, "1fcbb01852003d60b66024c508608baa2c21af1e884cf31154d3077d4643cf2249eb2f5a68e4ba019d90211a81d690d9"}} {
		t.Run(tc.name, func(t *testing.T) {
			want, _ := hex.DecodeString(tc.want)
			got, e := tc.enc(h[:48], h[128:160], h[192:208])
			if e != nil || !bytes.Equal(got, want) {
				t.Fatalf("%x %v", got, e)
			}
			got, e = tc.dec(got, h[128:160], h[192:208])
			if e != nil || !bytes.Equal(got, h[:48]) {
				t.Fatal(e)
			}
		})
	}
	src := []uint16{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}
	got, e := FMTEncrypt(src, 10, h[128:160], h[192:208])
	if e != nil || !reflect.DeepEqual(got, []uint16{6, 9, 3, 4, 7, 7, 0, 3, 5, 2}) {
		t.Fatalf("%v %v", got, e)
	}
	got, e = FMTDecrypt(got, 10, h[128:160], h[192:208])
	if e != nil || !reflect.DeepEqual(got, src) {
		t.Fatal(e)
	}
}
func FuzzFMT(f *testing.F) {
	f.Add(uint16(10), []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9})
	f.Fuzz(func(t *testing.T, radix uint16, b []byte) {
		if radix < 2 || len(b) < 2 || len(b) > 100 {
			return
		}
		mod := uint32(radix)
		src := make([]uint16, len(b))
		for i, v := range b {
			src[i] = uint16(uint32(v) % mod)
		}
		key := make([]byte, 16)
		enc, e := FMTEncrypt(src, mod, key, nil)
		if e != nil {
			t.Fatal(e)
		}
		dec, e := FMTDecrypt(enc, mod, key, nil)
		if e != nil || !reflect.DeepEqual(src, dec) {
			t.Fatalf("roundtrip %v", e)
		}
		for _, v := range enc {
			if uint32(v) >= mod {
				t.Fatal("outside alphabet")
			}
		}
	})
}
func TestFMTRadixKAT(t *testing.T) {
	h := beltHBytes()
	for _, tc := range []struct {
		mod  uint32
		want []uint16
	}{{58, []uint16{7, 4, 6, 21, 49, 55, 24, 23, 22, 50, 27, 39, 24, 24, 17, 32, 57, 43, 26, 5, 29}}, {65536, []uint16{14290, 31359, 58054, 51842, 44653, 34762, 28652, 48929, 6541, 13788, 7784, 46182, 61098, 43056, 3564, 21568, 63878}}} {
		src := make([]uint16, len(tc.want))
		for i := range src {
			src[i] = uint16(i)
		}
		got, e := FMTEncrypt(src, tc.mod, h[128:160], h[192:208])
		if e != nil || !reflect.DeepEqual(got, tc.want) {
			t.Fatal(got, e)
		}
		got, e = FMTDecrypt(got, tc.mod, h[128:160], h[192:208])
		if e != nil || !reflect.DeepEqual(got, src) {
			t.Fatal(e)
		}
	}
}
