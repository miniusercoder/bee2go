package bpki

import (
	"bytes"
	"encoding/hex"
	"os"
	"strings"
	"testing"
)

func TestContainers(t *testing.T) {
	salt := []byte("12345678")
	for _, n := range []int{24, 32, 48, 64} {
		key := bytes.Repeat([]byte{byte(n)}, n)
		der, err := WrapPrivateKey(key, Protection{[]byte("zed"), salt, 10000})
		if err != nil {
			t.Fatal(err)
		}
		got, err := UnwrapPrivateKey(der, []byte("zed"))
		if err != nil || !bytes.Equal(got, key) {
			t.Fatalf("size %d: %x %v", n, got, err)
		}
		if got, err = UnwrapPrivateKey(der, []byte("bad")); err == nil || got != nil {
			t.Fatal("accepted wrong password")
		}
	}
	for _, n := range []int{17, 25, 33} {
		share := bytes.Repeat([]byte{42}, n)
		share[0] = 16
		der, err := WrapShare(share, Protection{[]byte("zed"), salt, 10000})
		if err != nil {
			t.Fatal(err)
		}
		got, err := UnwrapShare(der, []byte("zed"))
		if err != nil || !bytes.Equal(got, share) {
			t.Fatalf("size %d: %x %v", n, got, err)
		}
		der[len(der)-1] ^= 1
		if got, err = UnwrapShare(der, []byte("zed")); err == nil || got != nil {
			t.Fatal("accepted corruption")
		}
	}
	if _, err := WrapPrivateKey(make([]byte, 32), Protection{nil, salt, 9999}); err == nil {
		t.Fatal("accepted iterations")
	}
	if _, err := WrapPrivateKey(make([]byte, 31), Protection{nil, salt, 10000}); err == nil {
		t.Fatal("accepted key")
	}
	if _, err := WrapShare(make([]byte, 17), Protection{nil, salt, 10000}); err == nil {
		t.Fatal("accepted share id")
	}
	if _, err := WrapShare(append([]byte{1}, make([]byte, 16)...), Protection{nil, nil, 10000}); err == nil {
		t.Fatal("accepted salt")
	}
	if _, err := UnwrapPrivateKey([]byte{0x30, 0xff}, nil); err == nil {
		t.Fatal("accepted DER")
	}
}

func TestCSR(t *testing.T) {
	csr, _ := hex.DecodeString(csrHex)
	key, _ := hex.DecodeString("1F66B5B84B7339674533F0329C74F21834281FED0732429E0C79235FC273E269")
	expected, _ := hex.DecodeString("BD1A5650179D79E03FCEE49D4C2BD5DDF54CE46D0CF11E4FF87BF7A890857FD07AC6A60361E8C8173491686D461B2826190C2EDA5909054A9AB84D2AB9D99A90")
	if _, err := UnwrapCSR(csr); err != nil {
		t.Fatal(err)
	}
	rewritten, err := RewrapCSR(csr, key)
	if err != nil {
		t.Fatal(err)
	}
	got, err := UnwrapCSR(rewritten)
	if err != nil || !bytes.Equal(got, expected) {
		t.Fatalf("%x %v", got, err)
	}
	rewritten[len(rewritten)-1] ^= 1
	if got, err = UnwrapCSR(rewritten); err == nil || got != nil {
		t.Fatal("accepted invalid signature")
	}
	if _, err = RewrapCSR(csr, key[:24]); err == nil {
		t.Fatal("accepted wrong key size")
	}
}

const csrHex = "3082017A30820134020100305F3115301306035504030C0C524F4245525420534D495448310E300C06035504040C05534D495448310F300D060355042A0C06524F42455254311830160603550405130F50415347422D353333333234343238310B3009060355040613024742305D3018060A2A7000020022652D0201060A2A7000020022652D0301034100F64CDDFFE4D546EF484471583FAEBA9A38061084E280BF996F90BA6AF0DB6620F59ABAA7AD29D4E7D1CA0C21DD9E32D485F9E740841F4317CA9481503D1F1B50A06F301F06092A864886F70D01090731120C102F494E464F3A65726970323334313233304C06092A864886F70D01090E313F303D30170603551D200410300E300C060A2A7000020022654E023D30220603551D11041B30198117726F626572742E736D697468406578616D706C652E756B300D06092A7000020022652D0C050003310082B4F9F934E3FD457F5DF06AE63A88E722E35D35F565551535BA94CEF9243011999DF2159E4F4BAC22AD8C3135A3BD26"

func FuzzCSR(f *testing.F) {
	csr, _ := hex.DecodeString(csrHex)
	f.Add(csr)
	f.Add([]byte{0x30, 0})
	f.Fuzz(func(t *testing.T, der []byte) {
		if len(der) > 4096 {
			return
		}
		_, _ = UnwrapCSR(der)
		_, _ = RewrapCSR(der, make([]byte, 32))
	})
}
func FuzzContainers(f *testing.F) {
	f.Add([]byte{0x30, 0})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, der []byte) {
		if len(der) > 4096 {
			return
		}
		_, _ = UnwrapPrivateKey(der, []byte("p"))
		_, _ = UnwrapShare(der, []byte("p"))
	})
}
func TestAuthenticationFailures(t *testing.T) {
	s := append([]byte{1}, make([]byte, 16)...)
	der, e := WrapShare(s, Protection{[]byte("password"), []byte("12345678"), 10000})
	if e != nil {
		t.Fatal(e)
	}
	if out, e := UnwrapShare(der, []byte("wrong")); e == nil || out != nil {
		t.Fatal("share authentication")
	}
	if out, e := UnwrapCSR([]byte{0x30, 0}); e == nil || out != nil {
		t.Fatal("malformed CSR")
	}
	if out, e := RewrapCSR([]byte{0x30, 0}, make([]byte, 32)); e == nil || out != nil {
		t.Fatal("malformed CSR")
	}
}
func TestContainerCVectors(t *testing.T) {
	h, _ := hex.DecodeString("B194BAC80A08F53B366D008E584A5DE48504FA9D1BB6C7AC252E72C202FDCE0D5BE3D61217B96181FE6786AD716B890B5CB0C0FF33C356B835C405AED8E07F99E12BDC1AE28257EC")
	key := h[:24]
	p := Protection{[]byte("zed"), h[24:32], 10000}
	want, _ := hex.DecodeString("308195304806092A864886F70D01050D303B302A06092A864886F70D01050C301D0408252E72C202FDCE0D02022710300D06092A7000020022652F0C0500300D06092A7000020022651F4905000449F72B041639F1B98071E9BD47F10977C65C64EAA8BF6D08AB40A1437A53038D1D45FB56714212E44C57ED8DD8ED5718A114097C163045A0E8C210AF044FC592EEF1165E31CE29215910")
	der, e := WrapPrivateKey(key, p)
	if e != nil || !bytes.Equal(der, want) {
		t.Fatalf("%X %v", der, e)
	}
	got, e := UnwrapPrivateKey(want, []byte("zed"))
	if e != nil || !bytes.Equal(got, key) {
		t.Fatal(e)
	}
	share := append([]byte{1}, h[:16]...)
	want, _ = hex.DecodeString("30818D304806092A864886F70D01050D303B302A06092A864886F70D01050C301D0408E12BDC1AE28257EC02022713300D06092A7000020022652F0C0500300D06092A7000020022651F4905000441C587006357BA4850801EB3F02A6A28E58C272ED49488006E46DC703189834AE1A479B8A021F9E45A6B6CF45F905D7E2B5D654B5BF46A1CDD365193A82295C9F1A7")
	der, e = WrapShare(share, Protection{[]byte("zed"), h[64:72], 10003})
	if e != nil || !bytes.Equal(der, want) {
		t.Fatalf("%X %v", der, e)
	}
	got, e = UnwrapShare(want, []byte("zed"))
	if e != nil || !bytes.Equal(got, share) {
		t.Fatal(e)
	}
}
func TestAllContainerCVectors(t *testing.T) {
	raw, e := os.ReadFile("testdata/vectors.txt")
	if e != nil {
		t.Fatal(e)
	}
	vectors := strings.Fields(string(raw))
	if len(vectors) != 7 {
		t.Fatal("missing C vectors")
	}
	h, _ := hex.DecodeString("B194BAC80A08F53B366D008E584A5DE48504FA9D1BB6C7AC252E72C202FDCE0D5BE3D61217B96181FE6786AD716B890B5CB0C0FF33C356B835C405AED8E07F99E12BDC1AE28257EC")
	for i, n := range []int{24, 32, 48, 64} {
		key := h[:n]
		want, _ := hex.DecodeString(vectors[i])
		der, e := WrapPrivateKey(key, Protection{[]byte("zed"), h[[]int{24, 32, 40, 48}[i]:][:8], 10000 + i})
		if e != nil || !bytes.Equal(der, want) {
			t.Fatalf("key %d: %x %v", n, der, e)
		}
		got, e := UnwrapPrivateKey(want, []byte("zed"))
		if e != nil || !bytes.Equal(got, key) {
			t.Fatal(n, e)
		}
	}
	for i, n := range []int{16, 24, 32} {
		id := byte(i + 1)
		if i == 2 {
			id = 16
		}
		share := append([]byte{id}, h[:n]...)
		want, _ := hex.DecodeString(vectors[4+i])
		der, e := WrapShare(share, Protection{[]byte("zed"), h[64:72], 10003 + i})
		if e != nil || !bytes.Equal(der, want) {
			t.Fatalf("share %d: %x %v", n, der, e)
		}
		got, e := UnwrapShare(want, []byte("zed"))
		if e != nil || !bytes.Equal(got, share) {
			t.Fatal(n, e)
		}
	}
}
