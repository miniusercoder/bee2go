package belt

import (
	"crypto/subtle"
	bee2 "github.com/miniusercoder/bee2go/v3"
	"github.com/miniusercoder/bee2go/v3/internal/native"
)

// HashN returns the first n bytes of the BELT hash, for 0 <= n <= 32.
func HashN(src []byte, n int) ([]byte, error) {
	if n < 0 || n > 32 {
		return nil, bee2.ErrInvalidInput
	}
	v, e := Hash(src)
	if e != nil {
		return nil, e
	}
	out := append([]byte{}, v[:n]...)
	native.Wipe(v)
	return out, nil
}
func HashVerify(src, expected []byte) (bool, error) {
	v, e := HashN(src, len(expected))
	if e != nil {
		return false, e
	}
	defer native.Wipe(v)
	return subtle.ConstantTimeCompare(v, expected) == 1, nil
}
func macN(hmac bool, src, key []byte, n int) ([]byte, error) {
	max := 8
	if hmac {
		max = 32
	}
	if n < 0 || n > max {
		return nil, bee2.ErrInvalidInput
	}
	v, e := native.BeltMAC(hmac, src, key)
	if e != nil {
		return nil, e
	}
	out := append([]byte{}, v[:n]...)
	native.Wipe(v)
	return out, nil
}
func MACN(src, key []byte, n int) ([]byte, error)  { return macN(false, src, key, n) }
func HMACN(src, key []byte, n int) ([]byte, error) { return macN(true, src, key, n) }
func MACVerify(src, key, expected []byte) (bool, error) {
	v, e := MACN(src, key, len(expected))
	if e != nil {
		return false, e
	}
	defer native.Wipe(v)
	return subtle.ConstantTimeCompare(v, expected) == 1, nil
}
func HMACVerify(src, key, expected []byte) (bool, error) {
	v, e := HMACN(src, key, len(expected))
	if e != nil {
		return false, e
	}
	defer native.Wipe(v)
	return subtle.ConstantTimeCompare(v, expected) == 1, nil
}
