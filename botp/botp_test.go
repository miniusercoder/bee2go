package botp

import (
	"encoding/hex"
	"errors"
	"fmt"
	bee2 "github.com/miniusercoder/bee2go/v3"
	"math"
	"testing"
)

func TestHOTPAndTOTP(t *testing.T) {
	key, _ := hex.DecodeString("E9DEE72C8F0C0FA62DDB49F46F73964706075316ED247A3739CBA38303A98BF6")
	ctr := [8]byte{0xBE, 0x32, 0x97, 0x13, 0x43, 0xFC, 0x9A, 0x48}
	h, err := NewHOTP(key, 8, ctr)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	for _, want := range []string{"21157984", "17877985", "26078636"} {
		got, err := h.Next()
		if err != nil || got != want {
			t.Fatalf("%q %v", got, err)
		}
	}
	h.SetCounter(ctr)
	if ok, err := h.Verify("00000000"); err != nil || ok || counter(t, h) != ctr {
		t.Fatal("bad verification changed state")
	}
	if ok, err := h.Verify("21157984"); err != nil || !ok || counter(t, h) == ctr {
		t.Fatal("correct verification did not advance")
	}
	got, err := HOTPCode(key, 8, ctr)
	if err != nil || got != "21157984" {
		t.Fatal(got, err)
	}
	for i, want := range []string{"97660664", "94431522", "55973851"} {
		got, err := TOTPCode(key, 8, 1449165288/60+int64(i))
		if err != nil || got != want {
			t.Fatal(got, err)
		}
	}
	if _, err := TOTPCode(key, 5, 0); err == nil {
		t.Fatal("digits")
	}
	if _, err := TOTPCode(key, 8, -1); err == nil {
		t.Fatal("time")
	}
}
func TestOCRA(t *testing.T) {
	key, _ := hex.DecodeString("E9DEE72C8F0C0FA62DDB49F46F73964706075316ED247A3739CBA38303A98BF6")
	h, _ := hex.DecodeString("B194BAC80A08F53B366D008E584A5DE48504FA9D1BB6C7AC252E72C202FDCE0D5BE3D61217B96181FE6786AD716B890B5CB0C0FF33C356B835C405AED8E07F99")
	p, e := hex.DecodeString("ABEF9725D4C5A83597A367D14494CC2542F20F659DDFECC961A3EC550CBA8C75")
	if e != nil {
		t.Fatal(e)
	}
	ctr := [8]byte{0xbe, 0x32, 0x97, 0x13, 0x43, 0xfc, 0x9a, 0x48}
	hs, _ := NewHOTP(key, 8, ctr)
	defer hs.Close()
	for i := 0; i < 3; i++ {
		hs.Next()
	}
	ctr = counter(t, hs)
	suite, e := ParseSuite("OCRA-1:HOTP-HBELT-8:C-QN08-PHBELT-S064-T1M")
	if e != nil {
		t.Fatal(e)
	}
	o, e := NewOCRA(suite, key, ctr, p, h)
	if e != nil {
		t.Fatal(e)
	}
	defer o.Close()
	step := int64(1449165288/60 + 1 + 2 - 1 + 3)
	got, e := o.Next("21157984", step)
	if e != nil || got != "85199085" {
		t.Fatal(got, e)
	}
	o.SetCounter(ctr)
	ok, e := o.Verify(got, "21157984", step)
	if e != nil || !ok {
		t.Fatal(ok, e)
	}
	got, e = o.Next("1787798526078636", step+10)
	if e != nil || got != "89873725" {
		t.Fatal(got, e)
	}
	got, e = o.Next("2607863617877985", step+11)
	if e != nil || got != "21318915" {
		t.Fatal(got, e)
	}
	for _, bad := range []string{"OCRA-:HOTP-HBELT-6:C-QN08", "OCRA-1:HOTP-HBELT-3:C-QN08", "OCRA-1:HOTP-HBELT-8:C-QA65"} {
		if _, e := ParseSuite(bad); e == nil {
			t.Fatal(bad)
		}
	}
	if _, e = o.Next("foo", step); e == nil {
		t.Fatal("short query")
	}
}

func counter(t *testing.T, h *HOTP) [8]byte {
	t.Helper()
	c, e := h.Counter()
	if e != nil {
		t.Fatal(e)
	}
	return c
}
func TestVerificationAndTOTPState(t *testing.T) {
	key, _ := hex.DecodeString("E9DEE72C8F0C0FA62DDB49F46F73964706075316ED247A3739CBA38303A98BF6")
	ctr := [8]byte{0xbe, 0x32, 0x97, 0x13, 0x43, 0xfc, 0x9a, 0x48}
	if ok, e := VerifyHOTP("21157984", key, ctr); e != nil || !ok {
		t.Fatal(ok, e)
	}
	if ok, _ := VerifyHOTP("11111111", key, ctr); ok {
		t.Fatal("incorrect")
	}
	s, e := NewTOTP(key, 8)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	got, e := s.Code(1449165288 / 60)
	if e != nil || got != "97660664" {
		t.Fatal(got, e)
	}
	if ok, e := s.Verify(got, 1449165288/60); e != nil || !ok {
		t.Fatal(ok, e)
	}
	if ok, e := VerifyTOTP(got, key, 1449165288/60); e != nil || !ok {
		t.Fatal(ok, e)
	}
}
func TestOCRAOneShot(t *testing.T) {
	s, e := ParseSuite("OCRA-1:HOTP-HBELT-6:QN08")
	if e != nil {
		t.Fatal(e)
	}
	key := []byte("12345678901234567890123456789012")
	var ctr [8]byte
	code, e := OCRACode(s, key, "12345678", ctr, nil, nil, 0)
	if e != nil {
		t.Fatal(e)
	}
	if ok, e := VerifyOCRA(code, s, key, "12345678", ctr, nil, nil, 0); e != nil || !ok {
		t.Fatal(ok, e)
	}
	if ok, e := VerifyOCRA("000000", s, key, "12345678", ctr, nil, nil, 0); e != nil || ok {
		t.Fatal(ok, e)
	}
}
func TestOCRAStateAndLeadingZero(t *testing.T) {
	s, _ := ParseSuite("OCRA-1:HOTP-HBELT-6:C-QN08")
	key := []byte("12345678901234567890123456789012")
	var ctr [8]byte
	o, e := NewOCRA(s, key, ctr, nil, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer o.Close()
	code, e := o.Next("12345678", 0)
	if e != nil {
		t.Fatal(e)
	}
	if e = o.SetCounter(ctr); e != nil {
		t.Fatal(e)
	}
	if ok, e := o.Verify("xxxxxx", "12345678", 0); e != nil || ok {
		t.Fatal(ok, e)
	}
	got, e := o.Counter()
	if e != nil || got != ctr {
		t.Fatal(got, e)
	}
	if ok, e := o.Verify(code, "12345678", 0); e != nil || !ok {
		t.Fatal(ok, e)
	}
	got, e = o.Counter()
	if e != nil || got == ctr {
		t.Fatal(got, e)
	}
	found := false
	for i := 0; i < 500; i++ {
		ctr[0] = byte(i)
		ctr[1] = byte(i >> 8)
		code, e := HOTPCode(key, 6, ctr)
		if e != nil {
			t.Fatal(e)
		}
		if code[0] == '0' {
			if len(code) != 6 {
				t.Fatal(code)
			}
			found = true
			break
		}
	}
	if !found {
		t.Fatal("leading zero not found")
	}
}
func FuzzParseSuite(f *testing.F) {
	for _, s := range []string{"OCRA-1:HOTP-HBELT-6:QN08", "OCRA-1:HOTP-HBELT-8:C-QN08-PHBELT-S064-T1M", "", "\x00"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		suite, e := ParseSuite(s)
		if e == nil {
			var ctr [8]byte
			o, e := NewOCRA(suite, []byte("key"), ctr, make([]byte, suite.plen), make([]byte, suite.slen))
			if e != nil {
				t.Fatal(e)
			}
			o.Close()
		}
	})
}
func TestSuiteFields(t *testing.T) {
	s, e := ParseSuite("OCRA-1:HOTP-HBELT-8:C-QN08-PHBELT-S064-T1M")
	if e != nil {
		t.Fatal(e)
	}
	if s.Digits() != 8 || s.ChallengeType() != 'N' || s.ChallengeMax() != 8 || !s.HasCounter() || s.PasswordHashSize() != 32 || s.SessionSize() != 64 || s.TimeStep() != 60 {
		t.Fatal("incorrect parsed suite")
	}
}
func TestCounterBoundaryAndClose(t *testing.T) {
	key := []byte("key")
	ctr := [8]byte{255, 255, 255, 255, 255, 255, 255, 255}
	h, e := NewHOTP(key, 6, ctr)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = h.Next(); e != nil {
		t.Fatal(e)
	}
	got, e := h.Counter()
	if e != nil || got != ([8]byte{}) {
		t.Fatal(got, e)
	}
	if e = h.Close(); e != nil {
		t.Fatal(e)
	}
	if _, e = h.Next(); e == nil {
		t.Fatal("closed HOTP")
	}
	tt, e := NewTOTP(key, 6)
	if e != nil {
		t.Fatal(e)
	}
	tt.Close()
	if _, e = tt.Code(0); e == nil {
		t.Fatal("closed TOTP")
	}
}
func TestOCRASessionLengths(t *testing.T) {
	s, _ := ParseSuite("OCRA-1:HOTP-HBELT-8:C-QN08-PHBELT-S064-T1M")
	var ctr [8]byte
	for _, v := range []struct{ p, s []byte }{{nil, make([]byte, 64)}, {make([]byte, 32), nil}} {
		if _, e := NewOCRA(s, []byte("key"), ctr, v.p, v.s); e == nil {
			t.Fatal("accepted missing field")
		}
	}
}

func TestDigitLengths(t *testing.T) {
	key := []byte("test key")
	var ctr [8]byte
	for digits := 6; digits <= 8; digits++ {
		h, e := NewHOTP(key, digits, ctr)
		if e != nil {
			t.Fatal(e)
		}
		code, e := h.Next()
		if e != nil || len(code) != digits {
			t.Fatal(code, e)
		}
		h.Close()
		one, e := HOTPCode(key, digits, ctr)
		if e != nil || one != code {
			t.Fatal(one, e)
		}
		tt, e := NewTOTP(key, digits)
		if e != nil {
			t.Fatal(e)
		}
		code, e = tt.Code(0)
		if e != nil || len(code) != digits {
			t.Fatal(code, e)
		}
		tt.Close()
		one, e = TOTPCode(key, digits, 0)
		if e != nil || one != code {
			t.Fatal(one, e)
		}
	}
	for digits := 4; digits <= 9; digits++ {
		s, e := ParseSuite(fmt.Sprintf("OCRA-1:HOTP-HBELT-%d:QN08", digits))
		if e != nil {
			t.Fatal(e)
		}
		code, e := OCRACode(s, key, "12345678", ctr, nil, nil, 0)
		if e != nil || len(code) != digits {
			t.Fatal(code, e)
		}
	}
}
func TestClosedStatePrecedence(t *testing.T) {
	key := []byte("key")
	h, e := NewHOTP(key, 6, [8]byte{})
	if e != nil {
		t.Fatal(e)
	}
	h.Close()
	if _, e = h.Verify("bad"); !errors.Is(e, bee2.ErrClosed) {
		t.Fatal(e)
	}
	if e = h.SetCounter([8]byte{}); !errors.Is(e, bee2.ErrClosed) {
		t.Fatal(e)
	}
	if _, e = h.Counter(); !errors.Is(e, bee2.ErrClosed) {
		t.Fatal(e)
	}
	tt, e := NewTOTP(key, 6)
	if e != nil {
		t.Fatal(e)
	}
	tt.Close()
	if _, e = tt.Code(-1); !errors.Is(e, bee2.ErrClosed) {
		t.Fatal(e)
	}
	if _, e = tt.Verify("bad", -1); !errors.Is(e, bee2.ErrClosed) {
		t.Fatal(e)
	}
	suite, _ := ParseSuite("OCRA-1:HOTP-HBELT-6:QN08")
	o, e := NewOCRA(suite, key, [8]byte{}, nil, nil)
	if e != nil {
		t.Fatal(e)
	}
	o.Close()
	if _, e = o.Next("x", -1); !errors.Is(e, bee2.ErrClosed) {
		t.Fatal(e)
	}
	if _, e = o.Verify("x", "x", -1); !errors.Is(e, bee2.ErrClosed) {
		t.Fatal(e)
	}
	if _, e = o.Counter(); !errors.Is(e, bee2.ErrClosed) {
		t.Fatal(e)
	}
	if e = o.SetCounter([8]byte{}); !errors.Is(e, bee2.ErrClosed) {
		t.Fatal(e)
	}
}
func TestNegativeTimeCVectors(t *testing.T) {
	key := []byte("key")
	suite, e := ParseSuite("OCRA-1:HOTP-HBELT-6:QN08-T1M")
	if e != nil {
		t.Fatal(e)
	}
	var ctr [8]byte
	for i, step := range []int64{-2, math.MinInt64} {
		want := []string{"57055152", "97959717"}[i]
		code, e := TOTPCode(key, 8, step)
		if e != nil || code != want {
			t.Fatal(code, e)
		}
		s, e := NewTOTP(key, 8)
		if e != nil {
			t.Fatal(e)
		}
		got, e := s.Code(step)
		if e != nil || got != want {
			t.Fatal(got, e)
		}
		ok, e := s.Verify(want, step)
		if e != nil || !ok {
			t.Fatal(ok, e)
		}
		s.Close()
		ok, e = VerifyTOTP(want, key, step)
		if e != nil || !ok {
			t.Fatal(ok, e)
		}
		want = []string{"090828", "633279"}[i]
		code, e = OCRACode(suite, key, "12345678", ctr, nil, nil, step)
		if e != nil || code != want {
			t.Fatal(code, e)
		}
		o, e := NewOCRA(suite, key, ctr, nil, nil)
		if e != nil {
			t.Fatal(e)
		}
		got, e = o.Next("12345678", step)
		if e != nil || got != want {
			t.Fatal(got, e)
		}
		ok, e = o.Verify(want, "12345678", step)
		if e != nil || !ok {
			t.Fatal(ok, e)
		}
		o.Close()
	}
	if _, e = TOTPCode(key, 8, -1); e == nil {
		t.Fatal("TIME_ERR")
	}
	if _, e = OCRACode(suite, key, "12345678", ctr, nil, nil, -1); e == nil {
		t.Fatal("OCRA TIME_ERR")
	}
	noTime, _ := ParseSuite("OCRA-1:HOTP-HBELT-6:QN08")
	code, e := OCRACode(noTime, key, "12345678", ctr, nil, nil, -1)
	if e != nil || code != "101476" {
		t.Fatal(code, e)
	}
	o, e := NewOCRA(noTime, key, ctr, nil, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer o.Close()
	got, e := o.Next("12345678", -1)
	if e != nil || got != code {
		t.Fatal(got, e)
	}
	ok, e := o.Verify(code, "12345678", -1)
	if e != nil || !ok {
		t.Fatal(ok, e)
	}
}
