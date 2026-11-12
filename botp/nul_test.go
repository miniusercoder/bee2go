package botp

import "testing"

func TestOneShotOTPRejectsEmbeddedNUL(t *testing.T) {
	key := []byte("key")
	var ctr [8]byte
	h, e := HOTPCode(key, 6, ctr)
	if e != nil {
		t.Fatal(e)
	}
	totp, e := TOTPCode(key, 6, 5)
	if e != nil {
		t.Fatal(e)
	}
	suite, e := ParseSuite("OCRA-1:HOTP-HBELT-6:QN08")
	if e != nil {
		t.Fatal(e)
	}
	o, e := OCRACode(suite, key, "12345678", ctr, nil, nil, 0)
	if e != nil {
		t.Fatal(e)
	}
	for _, suffix := range []string{"\x00x", "\x00", "a"} {
		if ok, e := VerifyHOTP(h+suffix, key, ctr); ok || e == nil {
			t.Fatalf("HOTP suffix %q accepted: %v %v", suffix, ok, e)
		}
		if ok, e := VerifyTOTP(totp+suffix, key, 5); ok || e == nil {
			t.Fatalf("TOTP suffix %q accepted: %v %v", suffix, ok, e)
		}
		if ok, e := VerifyOCRA(o+suffix, suite, key, "12345678", ctr, nil, nil, 0); ok || e == nil {
			t.Fatalf("OCRA suffix %q accepted: %v %v", suffix, ok, e)
		}
	}
}
func TestOneShotOTPRejectsNULAtEveryPosition(t *testing.T) {
	key := []byte("key")
	var ctr [8]byte
	for digits := 6; digits <= 8; digits++ {
		h, e := HOTPCode(key, digits, ctr)
		if e != nil {
			t.Fatal(e)
		}
		totp, e := TOTPCode(key, digits, 5)
		if e != nil {
			t.Fatal(e)
		}
		for i := 0; i < digits; i++ {
			bad := []byte(h)
			bad[i] = 0
			if ok, _ := VerifyHOTP(string(bad), key, ctr); ok {
				t.Fatal("HOTP NUL position", i)
			}
			bad = []byte(totp)
			bad[i] = 0
			if ok, _ := VerifyTOTP(string(bad), key, 5); ok {
				t.Fatal("TOTP NUL position", i)
			}
		}
	}
}
