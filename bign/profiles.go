package bign

import (
	"github.com/miniusercoder/bee2go/v3/internal/native"
	"io"
)

// Profile fixes the curve and hash OID. Profile96 is the upstream experimental
// BIGN96 construction, with its own 34-byte signature format.
type Profile int

const (
	Profile96  Profile = 96
	Profile128 Profile = 128
	Profile192 Profile = 192
	Profile256 Profile = 256
)

func (p Profile) DigestSize() int {
	switch p {
	case Profile96, Profile128, Profile192, Profile256:
		return int(p) / 4
	}
	return 0
}
func (p Profile) GenerateKey(r io.Reader) ([]byte, []byte, error) {
	return native.BignProfileKey(int(p), r)
}
func (p Profile) ValidateKeyPair(a, b []byte) error  { return native.BignProfilePair(int(p), a, b) }
func (p Profile) ValidatePublicKey(b []byte) error   { return native.BignProfileValidate(int(p), b) }
func (p Profile) PublicKey(a []byte) ([]byte, error) { return native.BignProfilePublic(int(p), a) }
func (p Profile) SignDigest(h, a []byte, r io.Reader) ([]byte, error) {
	return native.BignProfileSign(int(p), h, a, r)
}
func (p Profile) SignDigestDeterministic(h, a, t []byte) ([]byte, error) {
	return native.BignProfileSign2(int(p), h, a, t)
}
func (p Profile) VerifyDigest(h, sig, b []byte) error {
	return native.BignProfileVerify(int(p), h, sig, b)
}
func (p Profile) DH(a, b []byte, n int) ([]byte, error) { return native.BignProfileDH(int(p), a, b, n) }
func (p Profile) WrapKey(key, header, b []byte, r io.Reader) ([]byte, error) {
	return native.BignProfileWrap(int(p), key, header, b, r)
}
func (p Profile) UnwrapKey(token, header, a []byte) ([]byte, error) {
	return native.BignProfileUnwrap(int(p), token, header, a)
}
