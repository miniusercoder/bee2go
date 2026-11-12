package bee2go

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// ────────────────────────────────────────────────────────────────────────────
// Helpers
// ────────────────────────────────────────────────────────────────────────────

// hd decodes a compact hex string (no spaces) — panics on bad input.
func hd(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic("bad hex: " + s)
	}
	return b
}

// ────────────────────────────────────────────────────────────────────────────
// belt-hash KAT (STB 34.101.31 table A.23)
// ────────────────────────────────────────────────────────────────────────────

func TestBeltHashKAT(t *testing.T) {
	H := beltHBytes() // 256-byte S-box from belt

	tests := []struct {
		n    int
		want string
	}{
		// A.23-1: hash(H[0:13])
		{13, "ABEF9725D4C5A83597A367D14494CC2542F20F659DDFECC961A3EC550CBA8C75"},
		// A.23-2: hash(H[0:32])
		{32, "749E4C3653AECE5E48DB4761227742EB6DBE13F4A80F7BEFF1A9CF8D10EE7786"},
		// A.23-3: hash(H[0:48])
		{48, "9D02EE446FB6A29FE5C982D4B13AF9D3E90861BC4CEF27CF306BFB0B174A154A"},
	}

	for _, tc := range tests {
		got, err := BeltHash(H[:tc.n])
		if err != nil {
			t.Errorf("n=%d: %v", tc.n, err)
			continue
		}
		want := hd(tc.want)
		if !bytes.Equal(got, want) {
			t.Errorf("n=%d:\ngot  %X\nwant %X", tc.n, got, want)
		}
	}
}

// hash.Hash interface: Size, BlockSize, idempotent Sum, Reset
func TestBeltHashInterface(t *testing.T) {
	h, err := NewBeltHash()
	if err != nil {
		t.Fatal(err)
	}
	bh := h.(*beltHash)
	defer bh.Free()

	if h.Size() != 32 {
		t.Errorf("Size=%d want 32", h.Size())
	}
	if h.BlockSize() != 32 {
		t.Errorf("BlockSize=%d want 32", h.BlockSize())
	}

	H := beltHBytes()
	_, _ = h.Write(H[:48])
	s1 := h.Sum(nil)
	s2 := h.Sum(nil)
	if !bytes.Equal(s1, s2) {
		t.Fatal("Sum not idempotent")
	}
}

// Incremental write must match single-call.
func TestBeltHashIncremental(t *testing.T) {
	H := beltHBytes()
	ref, _ := BeltHash(H[:48])

	h, _ := NewBeltHash()
	bh := h.(*beltHash)
	defer bh.Free()

	h.Write(H[:11])
	h.Write(H[11:48])
	got := h.Sum(nil)
	if !bytes.Equal(got, ref) {
		t.Errorf("incremental mismatch:\ngot  %X\nwant %X", got, ref)
	}
}

// ────────────────────────────────────────────────────────────────────────────
// belt-ECB KAT (STB 34.101.31 table A.9)
// ────────────────────────────────────────────────────────────────────────────

func TestBeltECBKAT(t *testing.T) {
	H := beltHBytes()
	key := H[128:160] // 32-byte key at H[128]
	src := H[0:48]    // 48 bytes = 3 blocks

	wantEnc := hd("69CCA1C93557C9E3D66BC3E0FA88FA6E" +
		"5F23102EF109710775017F73806DA9DC" +
		"46FB2ED2CE771F26DCB5E5D1569F9AB0")

	enc, err := BeltECBEncr(src, key)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(enc, wantEnc) {
		t.Errorf("ECB encrypt:\ngot  %X\nwant %X", enc, wantEnc)
	}

	dec, err := BeltECBDecr(enc, key)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dec, src) {
		t.Fatal("ECB decrypt did not recover plaintext")
	}
}

// ────────────────────────────────────────────────────────────────────────────
// belt-CBC round-trip (multiple key lengths)
// ────────────────────────────────────────────────────────────────────────────

func TestBeltCBCRoundTrip(t *testing.T) {
	H := beltHBytes()
	iv := H[192:208]

	for _, keyLen := range []int{16, 32} {
		key := H[128 : 128+keyLen]
		plain := H[:48]

		enc, err := BeltCBCEncr(plain, key, iv)
		if err != nil {
			t.Fatalf("keyLen=%d Encr: %v", keyLen, err)
		}
		if bytes.Equal(enc, plain) {
			t.Fatalf("keyLen=%d CBC did not change plaintext", keyLen)
		}

		dec, err := BeltCBCDecr(enc, key, iv)
		if err != nil {
			t.Fatalf("keyLen=%d Decr: %v", keyLen, err)
		}
		if !bytes.Equal(dec, plain) {
			t.Errorf("keyLen=%d round-trip failed", keyLen)
		}
	}
}

// ────────────────────────────────────────────────────────────────────────────
// belt-CFB round-trip
// ────────────────────────────────────────────────────────────────────────────

func TestBeltCFBRoundTrip(t *testing.T) {
	H := beltHBytes()
	key := H[128:160]
	iv := H[192:208]
	plain := H[:32]

	enc, err := BeltCFBEncr(plain, key, iv)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := BeltCFBDecr(enc, key, iv)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dec, plain) {
		t.Fatal("CFB round-trip failed")
	}
}

// ────────────────────────────────────────────────────────────────────────────
// belt-CTR symmetric (encrypt == decrypt)
// ────────────────────────────────────────────────────────────────────────────

func TestBeltCTRSymmetric(t *testing.T) {
	H := beltHBytes()
	key := H[128:160]
	iv := H[192:208]
	plain := H[:37]

	enc, _ := BeltCTR(plain, key, iv)
	dec, _ := BeltCTR(enc, key, iv)
	if !bytes.Equal(dec, plain) {
		t.Fatal("CTR decrypt != original plaintext")
	}

	// Different IV must produce different ciphertext.
	iv2 := make([]byte, 16)
	copy(iv2, iv)
	iv2[0] ^= 0xFF
	enc2, _ := BeltCTR(plain, key, iv2)
	if bytes.Equal(enc, enc2) {
		t.Fatal("CTR: different IVs produced same ciphertext")
	}
}

// ────────────────────────────────────────────────────────────────────────────
// belt-MAC KAT (STB 34.101.31 table A.17)
// ────────────────────────────────────────────────────────────────────────────

func TestBeltMACKAT(t *testing.T) {
	H := beltHBytes()
	key := H[128:160]

	// A.17-2: MAC(H[0:48], key)
	mac, err := BeltMAC(H[:48], key)
	if err != nil {
		t.Fatal(err)
	}
	want := hd("2DAB59771B4B16D0")
	if !bytes.Equal(mac, want) {
		t.Errorf("MAC:\ngot  %X\nwant %X", mac, want)
	}
}

// ────────────────────────────────────────────────────────────────────────────
// belt-DWP AEAD wrap/unwrap (STB 34.101.31 table A.19-1)
// ────────────────────────────────────────────────────────────────────────────

func TestBeltDWPWrapUnwrap(t *testing.T) {
	H := beltHBytes()
	key := H[128:160]
	iv := H[192:208]
	plain := H[:16]
	aad := H[16:48]

	wantCT := hd("52C9AF96FF50F64435FC43DEF56BD797")
	wantMAC := hd("3B2E0AEB2B91854B")

	ct, mac, err := BeltDWPWrap(plain, aad, key, iv)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ct, wantCT) {
		t.Errorf("DWP ct:\ngot  %X\nwant %X", ct, wantCT)
	}
	if !bytes.Equal(mac, wantMAC) {
		t.Errorf("DWP mac:\ngot  %X\nwant %X", mac, wantMAC)
	}

	// Round-trip
	pt, err := BeltDWPUnwrap(ct, aad, mac, key, iv)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pt, plain) {
		t.Fatal("DWP Unwrap did not recover plaintext")
	}
}

// Tampered ciphertext must be rejected.
func TestBeltDWPTamper(t *testing.T) {
	H := beltHBytes()
	key := H[128:160]
	iv := H[192:208]
	plain := H[:16]
	aad := H[16:32]

	ct, mac, _ := BeltDWPWrap(plain, aad, key, iv)
	ct[0] ^= 0xFF
	if _, err := BeltDWPUnwrap(ct, aad, mac, key, iv); err == nil {
		t.Fatal("DWP Unwrap must fail on tampered ciphertext")
	}
}

// ────────────────────────────────────────────────────────────────────────────
// belt-CHE AEAD wrap/unwrap (STB 34.101.31 table A.19-2)
// ────────────────────────────────────────────────────────────────────────────

func TestBeltCHEWrapUnwrap(t *testing.T) {
	H := beltHBytes()
	key := H[128:160]
	iv := H[192:208]
	plain := H[:15]
	aad := H[16:48]

	wantCT := hd("BF3DAEAF5D18D2BCC30EA62D2E70A4")
	wantMAC := hd("548622B844123FF7")

	ct, mac, err := BeltCHEWrap(plain, aad, key, iv)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ct, wantCT) {
		t.Errorf("CHE ct:\ngot  %X\nwant %X", ct, wantCT)
	}
	if !bytes.Equal(mac, wantMAC) {
		t.Errorf("CHE mac:\ngot  %X\nwant %X", mac, wantMAC)
	}

	pt, err := BeltCHEUnwrap(ct, aad, mac, key, iv)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pt, plain) {
		t.Fatal("CHE Unwrap did not recover plaintext")
	}
}

// Tampered MAC must be rejected.
func TestBeltCHETamper(t *testing.T) {
	H := beltHBytes()
	key := H[128:160]
	iv := H[192:208]
	plain := H[:15]
	aad := H[16:32]

	ct, mac, _ := BeltCHEWrap(plain, aad, key, iv)
	mac[0] ^= 0xFF
	if _, err := BeltCHEUnwrap(ct, aad, mac, key, iv); err == nil {
		t.Fatal("CHE Unwrap must fail on tampered MAC")
	}
}

// ────────────────────────────────────────────────────────────────────────────
// belt-KWP round-trip
// ────────────────────────────────────────────────────────────────────────────

func TestBeltKWPRoundTrip(t *testing.T) {
	H := beltHBytes()
	wrapKey := H[128:160]
	innerKey := H[0:32]
	hdr := H[32:48]

	token, err := BeltKWPWrap(innerKey, hdr, wrapKey)
	if err != nil {
		t.Fatal(err)
	}
	if len(token) != len(innerKey)+16 {
		t.Fatalf("token length %d want %d", len(token), len(innerKey)+16)
	}

	recovered, err := BeltKWPUnwrap(token, hdr, wrapKey)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(recovered, innerKey) {
		t.Fatal("KWP Unwrap did not recover original key")
	}
}

// Wrong wrap-key must fail unwrap.
func TestBeltKWPWrongKey(t *testing.T) {
	H := beltHBytes()
	wrapKey := H[128:160]
	inner := H[0:32]

	token, _ := BeltKWPWrap(inner, nil, wrapKey)
	badKey := make([]byte, 32)
	copy(badKey, wrapKey)
	badKey[0] ^= 0xFF
	if _, err := BeltKWPUnwrap(token, nil, badKey); err == nil {
		t.Fatal("KWP must fail with wrong wrap key")
	}
}

// ────────────────────────────────────────────────────────────────────────────
// belt-HMAC KAT (STB 34.101.47 table Б.1)
// ────────────────────────────────────────────────────────────────────────────

func TestBeltHMACKAT(t *testing.T) {
	H := beltHBytes()

	tests := []struct {
		keyStart, keyEnd   int
		dataStart, dataEnd int
		want               string
	}{
		// Б.1-1: key=H[128:128+29], data=H[192:224]
		{128, 128 + 29, 192, 224,
			"D4828E6312B08BB83C9FA6535A463554" +
				"9E411FD11C0D8289359A1130E930676B"},
		// Б.1-2: key=H[128:160], data=H[192:224]
		{128, 160, 192, 224,
			"41FFE8645AEC0612E952D2CDF8DD508F" +
				"3E4A1D9B53F6A1DB293B19FE76B1879F"},
		// Б.1-3: key=H[128:128+42], data=H[192:224]
		{128, 128 + 42, 192, 224,
			"7D01B84D2315C332277B3653D7EC6470" +
				"7EBA7CDFF7FF70077B1DECBD68F2A144"},
	}

	for i, tc := range tests {
		got, err := BeltHMAC(H[tc.dataStart:tc.dataEnd], H[tc.keyStart:tc.keyEnd])
		if err != nil {
			t.Errorf("case %d: %v", i+1, err)
			continue
		}
		want := hd(tc.want)
		if !bytes.Equal(got, want) {
			t.Errorf("case %d:\ngot  %X\nwant %X", i+1, got, want)
		}
	}
}

// ────────────────────────────────────────────────────────────────────────────
// belt-PBKDF2 KAT (STB 34.101.45 table E.5 + additional)
// ────────────────────────────────────────────────────────────────────────────

func TestBeltPBKDF2KAT(t *testing.T) {
	// E.5 (STB 34.101.45): password = ASCII "B194BAC80A08F53B", iter=10000,
	// salt = H[192:200].  The password is the literal 16-char ASCII string, not
	// hex-decoded bytes.
	H := beltHBytes()

	pwd := []byte("B194BAC80A08F53B")
	iter := 10000
	salt := H[192:200]

	want := hd("3D331BBBB1FBBB40E4BF22F6CB9A689E" +
		"F13A77DC09ECF93291BFE42439A72E7D")

	got, err := BeltPBKDF2(pwd, iter, salt)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("PBKDF2 E.5:\ngot  %X\nwant %X", got, want)
	}

	// Additional OpenSSL-compatible vector: password="zed", iter=2048
	got2, err := BeltPBKDF2(
		[]byte("zed"), 2048,
		hd("49FEFF8076CD9480"),
	)
	if err != nil {
		t.Fatal(err)
	}
	want2 := hd("7249B4785FE68B1586D189A23E3842E4" +
		"8705C080A3248D8F0E8C3D63A93B2670")
	if !bytes.Equal(got2, want2) {
		t.Errorf("PBKDF2 zed/2048:\ngot  %X\nwant %X", got2, want2)
	}

	// Additional: password="zed", iter=10000
	got3, err := BeltPBKDF2(
		[]byte("zed"), 10000,
		hd("C65017E4F108BCF0"),
	)
	if err != nil {
		t.Fatal(err)
	}
	want3 := hd("E48329259BC1211DDAC2EF1DADFFC993" +
		"2702A92F1DD66C14A9BA1D7300C8713C")
	if !bytes.Equal(got3, want3) {
		t.Errorf("PBKDF2 zed/10000:\ngot  %X\nwant %X", got3, want3)
	}
}

// ────────────────────────────────────────────────────────────────────────────
// Error / edge-case coverage
// ────────────────────────────────────────────────────────────────────────────

func TestBeltInvalidKey(t *testing.T) {
	bad := make([]byte, 17) // not 16/24/32
	data := make([]byte, 16)
	iv := make([]byte, 16)

	if _, err := BeltECBEncr(data, bad); err == nil {
		t.Error("ECB bad key should fail")
	}
	if _, err := BeltCBCEncr(data, bad, iv); err == nil {
		t.Error("CBC bad key should fail")
	}
	if _, err := BeltCFBEncr(data, bad, iv); err == nil {
		t.Error("CFB bad key should fail")
	}
	if _, err := BeltCTR(data, bad, iv); err == nil {
		t.Error("CTR bad key should fail")
	}
	if _, err := BeltMAC(data, bad); err == nil {
		t.Error("MAC bad key should fail")
	}
}

func TestBeltPBKDF2InvalidIter(t *testing.T) {
	if _, err := BeltPBKDF2([]byte("pw"), 0, []byte("salt")); err == nil {
		t.Error("PBKDF2 iter=0 should fail")
	}
}

func TestBeltKWPTokenTooShort(t *testing.T) {
	wrapKey := make([]byte, 32)
	if _, err := BeltKWPUnwrap(make([]byte, 16), nil, wrapKey); err == nil {
		t.Error("KWP Unwrap with 16-byte token should fail")
	}
}
