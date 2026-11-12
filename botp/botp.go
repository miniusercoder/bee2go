// Package botp implements the Bee2 HOTP, TOTP and OCRA algorithms.
package botp

import "github.com/miniusercoder/bee2go/v3/internal/native"

type HOTP struct{ state *native.HOTP }

func NewHOTP(key []byte, digits int, ctr [8]byte) (*HOTP, error) {
	s, e := native.NewHOTP(key, digits, ctr)
	if e != nil {
		return nil, e
	}
	return &HOTP{s}, nil
}
func (h *HOTP) Close() error                    { return h.state.Close() }
func (h *HOTP) SetCounter(ctr [8]byte) error    { return h.state.SetCounter(ctr) }
func (h *HOTP) Counter() ([8]byte, error)       { return h.state.Counter() }
func (h *HOTP) Next() (string, error)           { return h.state.Next() }
func (h *HOTP) Verify(otp string) (bool, error) { return h.state.Verify(otp) }
func HOTPCode(key []byte, digits int, ctr [8]byte) (string, error) {
	return native.HOTPCode(key, digits, ctr)
}
func TOTPCode(key []byte, digits int, step int64) (string, error) {
	return native.TOTPCode(key, digits, step)
}

type TOTP struct{ state *native.TOTP }

func NewTOTP(key []byte, digits int) (*TOTP, error) {
	s, e := native.NewTOTP(key, digits)
	if e != nil {
		return nil, e
	}
	return &TOTP{s}, nil
}
func (t *TOTP) Close() error                                { return t.state.Close() }
func (t *TOTP) Code(step int64) (string, error)             { return t.state.Code(step) }
func (t *TOTP) Verify(otp string, step int64) (bool, error) { return t.state.Verify(otp, step) }
func VerifyHOTP(otp string, key []byte, ctr [8]byte) (bool, error) {
	return native.VerifyHOTP(otp, key, ctr)
}
func VerifyTOTP(otp string, key []byte, step int64) (bool, error) {
	return native.VerifyTOTP(otp, key, step)
}
