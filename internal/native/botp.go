package native

/*
#include "bridge.h"
#include <bee2/crypto/botp.h>
static int bee2go_time_fits(int64_t v) { if ((tm_time_t)-1 > 0 && v < 0) return 0; return (int64_t)(tm_time_t)v == v; }
*/
import "C"
import "unsafe"

func validOTPTime(t int64) bool { return t != -1 && C.bee2go_time_fits(C.int64_t(t)) != 0 }

type HOTP struct {
	s      *state
	digits int
}

func NewHOTP(key []byte, digits int, ctr [8]byte) (*HOTP, error) {
	if digits < 6 || digits > 8 {
		return nil, invalid("HOTP digits")
	}
	s, err := newState(uintptr(C.botpHOTP_keep()))
	if err != nil {
		return nil, err
	}
	C.botpHOTPStart(s.ptr, C.size_t(digits), octets(key), C.size_t(len(key)))
	C.botpHOTPStepS(s.ptr, octets(ctr[:]))
	return &HOTP{s, digits}, nil
}
func (h *HOTP) Close() error {
	if h == nil {
		return nil
	}
	return h.s.Close()
}
func (h *HOTP) SetCounter(ctr [8]byte) error {
	if h == nil {
		return invalid("HOTP")
	}
	if err := h.s.check(); err != nil {
		return err
	}
	C.botpHOTPStepS(h.s.ptr, octets(ctr[:]))
	return nil
}
func (h *HOTP) Counter() ([8]byte, error) {
	var ctr [8]byte
	if h == nil {
		return ctr, invalid("HOTP")
	}
	if err := h.s.check(); err != nil {
		return ctr, err
	}
	C.botpHOTPStepG(octets(ctr[:]), h.s.ptr)
	return ctr, nil
}
func (h *HOTP) Next() (string, error) {
	if h == nil {
		return "", invalid("HOTP")
	}
	if err := h.s.check(); err != nil {
		return "", err
	}
	out := make([]byte, h.digits+1)
	C.botpHOTPStepR((*C.char)(unsafe.Pointer(&out[0])), h.s.ptr)
	return string(out[:h.digits]), nil
}
func (h *HOTP) Verify(otp string) (bool, error) {
	if h == nil {
		return false, invalid("HOTP")
	}
	if err := h.s.check(); err != nil {
		return false, err
	}
	if len(otp) != h.digits {
		return false, nil
	}
	b := append([]byte(otp), 0)
	return C.botpHOTPStepV((*C.char)(unsafe.Pointer(&b[0])), h.s.ptr) != 0, nil
}
func HOTPCode(key []byte, digits int, ctr [8]byte) (string, error) {
	if digits < 6 || digits > 8 {
		return "", invalid("HOTP digits")
	}
	out := make([]byte, digits+1)
	err := codeErr("HOTP", C.botpHOTPRand((*C.char)(unsafe.Pointer(&out[0])), C.size_t(digits), octets(key), C.size_t(len(key)), octets(ctr[:])))
	if err != nil {
		return "", err
	}
	return string(out[:digits]), nil
}
func TOTPCode(key []byte, digits int, t int64) (string, error) {
	if digits < 6 || digits > 8 || !validOTPTime(t) {
		return "", invalid("TOTP")
	}
	out := make([]byte, digits+1)
	err := codeErr("TOTP", C.botpTOTPRand((*C.char)(unsafe.Pointer(&out[0])), C.size_t(digits), octets(key), C.size_t(len(key)), C.tm_time_t(t)))
	if err != nil {
		return "", err
	}
	return string(out[:digits]), nil
}

type OCRA struct {
	s            *state
	digits, qmax int
	qtype        byte
	hasTime      bool
}

func NewOCRA(suite string, key []byte, ctr [8]byte, p, session []byte, digits, qmax int, qtype byte, hasTime bool) (*OCRA, error) {
	s, e := newState(uintptr(C.botpOCRA_keep()))
	if e != nil {
		return nil, e
	}
	name := append([]byte(suite), 0)
	if C.botpOCRAStart(s.ptr, (*C.char)(unsafe.Pointer(&name[0])), octets(key), C.size_t(len(key))) == 0 {
		s.Close()
		return nil, invalid("OCRA suite")
	}
	C.botpOCRAStepS(s.ptr, octets(ctr[:]), octets(p), octets(session))
	return &OCRA{s, digits, qmax, qtype, hasTime}, nil
}
func (o *OCRA) Close() error {
	if o == nil {
		return nil
	}
	return o.s.Close()
}
func (o *OCRA) SetCounter(ctr [8]byte, p, session []byte) error {
	if o == nil {
		return invalid("OCRA")
	}
	if e := o.s.check(); e != nil {
		return e
	}
	C.botpOCRAStepS(o.s.ptr, octets(ctr[:]), octets(p), octets(session))
	return nil
}
func (o *OCRA) Counter() ([8]byte, error) {
	var ctr [8]byte
	if o == nil {
		return ctr, invalid("OCRA")
	}
	if e := o.s.check(); e != nil {
		return ctr, e
	}
	C.botpOCRAStepG(octets(ctr[:]), o.s.ptr)
	return ctr, nil
}
func (o *OCRA) check(q string, t int64) error {
	if o == nil {
		return invalid("OCRA")
	}
	if e := o.s.check(); e != nil {
		return e
	}
	if len(q) < 4 || len(q) > 2*o.qmax || (o.hasTime && !validOTPTime(t)) {
		return invalid("OCRA query")
	}
	for _, c := range []byte(q) {
		if !(c >= '0' && c <= '9' || o.qtype != 'N' && (c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z')) || o.qtype == 'H' && !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return invalid("OCRA query")
		}
	}
	return nil
}
func (o *OCRA) Next(q string, t int64) (string, error) {
	if e := o.check(q, t); e != nil {
		return "", e
	}
	if !o.hasTime {
		t = 0
	}
	out := make([]byte, o.digits+1)
	C.botpOCRAStepR((*C.char)(unsafe.Pointer(&out[0])), octets([]byte(q)), C.size_t(len(q)), C.tm_time_t(t), o.s.ptr)
	return string(out[:o.digits]), nil
}
func (o *OCRA) Verify(otp, q string, t int64) (bool, error) {
	if e := o.check(q, t); e != nil {
		return false, e
	}
	if !o.hasTime {
		t = 0
	}
	if len(otp) != o.digits {
		return false, nil
	}
	b := append([]byte(otp), 0)
	return C.botpOCRAStepV((*C.char)(unsafe.Pointer(&b[0])), octets([]byte(q)), C.size_t(len(q)), C.tm_time_t(t), o.s.ptr) != 0, nil
}

type TOTP struct {
	s      *state
	digits int
}

func NewTOTP(key []byte, digits int) (*TOTP, error) {
	if digits < 6 || digits > 8 {
		return nil, invalid("TOTP digits")
	}
	s, e := newState(uintptr(C.botpTOTP_keep()))
	if e != nil {
		return nil, e
	}
	C.botpTOTPStart(s.ptr, C.size_t(digits), octets(key), C.size_t(len(key)))
	return &TOTP{s, digits}, nil
}
func (t *TOTP) Close() error {
	if t == nil {
		return nil
	}
	return t.s.Close()
}
func (t *TOTP) Code(step int64) (string, error) {
	if t == nil {
		return "", invalid("TOTP")
	}
	if e := t.s.check(); e != nil {
		return "", e
	}
	if !validOTPTime(step) {
		return "", invalid("TOTP")
	}
	out := make([]byte, t.digits+1)
	C.botpTOTPStepR((*C.char)(unsafe.Pointer(&out[0])), C.tm_time_t(step), t.s.ptr)
	return string(out[:t.digits]), nil
}
func (t *TOTP) Verify(otp string, step int64) (bool, error) {
	if t == nil {
		return false, invalid("TOTP")
	}
	if e := t.s.check(); e != nil {
		return false, e
	}
	if !validOTPTime(step) {
		return false, invalid("TOTP")
	}
	if len(otp) != t.digits {
		return false, nil
	}
	b := append([]byte(otp), 0)
	return C.botpTOTPStepV((*C.char)(unsafe.Pointer(&b[0])), C.tm_time_t(step), t.s.ptr) != 0, nil
}
func VerifyHOTP(otp string, key []byte, ctr [8]byte) (bool, error) {
	if len(otp) < 6 || len(otp) > 8 {
		return false, nil
	}
	b := append([]byte(otp), 0)
	code := C.botpHOTPVerify((*C.char)(unsafe.Pointer(&b[0])), octets(key), C.size_t(len(key)), octets(ctr[:]))
	if code == C.ERR_BAD_PWD {
		return false, nil
	}
	return code == 0, codeErr("HOTP verify", code)
}
func VerifyTOTP(otp string, key []byte, step int64) (bool, error) {
	if !validOTPTime(step) {
		return false, invalid("TOTP")
	}
	if len(otp) < 6 || len(otp) > 8 {
		return false, nil
	}
	b := append([]byte(otp), 0)
	code := C.botpTOTPVerify((*C.char)(unsafe.Pointer(&b[0])), octets(key), C.size_t(len(key)), C.tm_time_t(step))
	if code == C.ERR_BAD_PWD {
		return false, nil
	}
	return code == 0, codeErr("TOTP verify", code)
}
func (o *OCRA) OneShot(suite string, key []byte, q string, ctr [8]byte, p, session []byte, step int64) (string, error) {
	if e := o.check(q, step); e != nil {
		return "", e
	}
	if !o.hasTime {
		step = 0
	}
	name := append([]byte(suite), 0)
	out := make([]byte, o.digits+1)
	e := codeErr("OCRA", C.botpOCRARand((*C.char)(unsafe.Pointer(&out[0])), (*C.char)(unsafe.Pointer(&name[0])), octets(key), C.size_t(len(key)), octets([]byte(q)), C.size_t(len(q)), octets(ctr[:]), octets(p), octets(session), C.tm_time_t(step)))
	if e != nil {
		return "", e
	}
	return string(out[:o.digits]), nil
}
func (o *OCRA) VerifyOneShot(otp, suite string, key []byte, q string, ctr [8]byte, p, session []byte, step int64) (bool, error) {
	if e := o.check(q, step); e != nil {
		return false, e
	}
	if !o.hasTime {
		step = 0
	}
	if len(otp) != o.digits {
		return false, nil
	}
	name := append([]byte(suite), 0)
	b := append([]byte(otp), 0)
	code := C.botpOCRAVerify((*C.char)(unsafe.Pointer(&b[0])), (*C.char)(unsafe.Pointer(&name[0])), octets(key), C.size_t(len(key)), octets([]byte(q)), C.size_t(len(q)), octets(ctr[:]), octets(p), octets(session), C.tm_time_t(step))
	if code == C.ERR_BAD_PWD {
		return false, nil
	}
	return code == 0, codeErr("OCRA verify", code)
}
