package native

/*
#include "bign_profiles.h"
*/
import "C"
import "io"

func profileSize(l int) int {
	switch l {
	case 96, 128, 192, 256:
		return l / 4
	}
	return 0
}
func profileSig(l int) int {
	if l == 96 {
		return 34
	}
	return 3 * l / 8
}
func BignProfileKey(l int, r io.Reader) ([]byte, []byte, error) {
	n := profileSize(l)
	if n == 0 {
		return nil, nil, invalid("bign.profile")
	}
	rng, e := NewRandom(r)
	if e != nil {
		return nil, nil, e
	}
	defer rng.Close()
	a, b := make([]byte, n), make([]byte, 2*n)
	e = codeErr("bign.profile.key", C.bee2go_bign_profile_key(C.int(l), octets(a), octets(b), rng.CTR.s.ptr))
	if e != nil {
		Wipe(a)
		return nil, nil, e
	}
	return a, b, nil
}
func BignProfilePair(l int, a, b []byte) error {
	n := profileSize(l)
	if n == 0 || len(a) != n || len(b) != 2*n {
		return invalid("bign.profile.pair")
	}
	return codeErr("bign.profile.pair", C.bee2go_bign_profile_pair(C.int(l), octets(a), octets(b)))
}
func BignProfileValidate(l int, b []byte) error {
	n := profileSize(l)
	if n == 0 || len(b) != 2*n {
		return invalid("bign.profile.pub")
	}
	return codeErr("bign.profile.pub", C.bee2go_bign_profile_val(C.int(l), octets(b)))
}
func BignProfilePublic(l int, a []byte) ([]byte, error) {
	n := profileSize(l)
	if n == 0 || len(a) != n {
		return nil, invalid("bign.profile.pub")
	}
	b := make([]byte, 2*n)
	if e := codeErr("bign.profile.pub", C.bee2go_bign_profile_pub(C.int(l), octets(b), octets(a))); e != nil {
		return nil, e
	}
	return b, nil
}
func BignProfileSign(l int, h, a []byte, r io.Reader) ([]byte, error) {
	n := profileSize(l)
	if n == 0 || len(h) != n || len(a) != n {
		return nil, invalid("bign.profile.sign")
	}
	rng, e := NewRandom(r)
	if e != nil {
		return nil, e
	}
	defer rng.Close()
	sig := make([]byte, profileSig(l))
	e = codeErr("bign.profile.sign", C.bee2go_bign_profile_sign(C.int(l), octets(sig), octets(h), octets(a), rng.CTR.s.ptr))
	if e != nil {
		Wipe(sig)
		return nil, e
	}
	return sig, nil
}
func BignProfileSign2(l int, h, a, t []byte) ([]byte, error) {
	n := profileSize(l)
	if n == 0 || len(h) != n || len(a) != n {
		return nil, invalid("bign.profile.sign2")
	}
	sig := make([]byte, profileSig(l))
	e := codeErr("bign.profile.sign2", C.bee2go_bign_profile_sign2(C.int(l), octets(sig), octets(h), octets(a), pointer(t), C.size_t(len(t))))
	if e != nil {
		Wipe(sig)
		return nil, e
	}
	return sig, nil
}
func BignProfileVerify(l int, h, sig, b []byte) error {
	n := profileSize(l)
	if n == 0 || len(h) != n || len(sig) != profileSig(l) || len(b) != 2*n {
		return invalid("bign.profile.verify")
	}
	return codeErr("bign.profile.verify", C.bee2go_bign_profile_verify(C.int(l), octets(h), octets(sig), octets(b)))
}
func BignProfileDH(l int, a, b []byte, n int) ([]byte, error) {
	z := profileSize(l)
	if l == 96 || z == 0 || len(a) != z || len(b) != 2*z || n < 0 || n > 2*z {
		return nil, invalid("bign.profile.dh")
	}
	out := make([]byte, n)
	if e := codeErr("bign.profile.dh", C.bee2go_bign_profile_dh(C.int(l), octets(out), octets(a), octets(b), C.size_t(n))); e != nil {
		Wipe(out)
		return nil, e
	}
	return out, nil
}
func BignProfileWrap(l int, key, header, pub []byte, r io.Reader) ([]byte, error) {
	z := profileSize(l)
	if l == 96 || z == 0 || len(key) < 16 || len(key) > int(^uint(0)>>1)-z-16 || (len(header) != 0 && len(header) != 16) || len(pub) != 2*z {
		return nil, invalid("bign.profile.wrap")
	}
	rng, e := NewRandom(r)
	if e != nil {
		return nil, e
	}
	defer rng.Close()
	out := make([]byte, len(key)+z+16)
	e = codeErr("bign.profile.wrap", C.bee2go_bign_profile_wrap(C.int(l), octets(out), octets(key), C.size_t(len(key)), octets(header), octets(pub), rng.CTR.s.ptr))
	if e != nil {
		Wipe(out)
		return nil, e
	}
	return out, nil
}
func BignProfileUnwrap(l int, token, header, priv []byte) ([]byte, error) {
	z := profileSize(l)
	if l == 96 || z == 0 || len(token) < z+32 || (len(header) != 0 && len(header) != 16) || len(priv) != z {
		return nil, invalid("bign.profile.unwrap")
	}
	out := make([]byte, len(token)-z-16)
	e := codeErr("bign.profile.unwrap", C.bee2go_bign_profile_unwrap(C.int(l), octets(out), octets(token), C.size_t(len(token)), octets(header), octets(priv)))
	if e != nil {
		Wipe(out)
		return nil, e
	}
	return out, nil
}
