package native

/*
#include "bridge.h"
#include <bee2/crypto/bels.h>
*/
import "C"
import (
	"bytes"
	"io"
)

func belsSize(n int) bool { return n == 16 || n == 24 || n == 32 }
func BELSStandard(n, index int) ([]byte, error) {
	if !belsSize(n) || index < 0 || index > 16 {
		return nil, invalid("bels standard")
	}
	out := make([]byte, n)
	if e := codeErr("bels standard", C.belsStdM(octets(out), C.size_t(n), C.size_t(index))); e != nil {
		return nil, e
	}
	return out, nil
}
func BELSValidate(m []byte) error {
	if !belsSize(len(m)) {
		return invalid("bels validate")
	}
	return codeErr("bels validate", C.belsValM(octets(m), C.size_t(len(m))))
}
func BELSDerive(m, id []byte) ([]byte, error) {
	if err := BELSValidate(m); err != nil {
		return nil, err
	}
	out := make([]byte, len(m))
	if e := codeErr("bels derive", C.belsGenMid(octets(out), C.size_t(len(m)), octets(m), octets(id), C.size_t(len(id)))); e != nil {
		return nil, e
	}
	return out, nil
}
func BELSShareDeterministic(secret []byte, count, threshold int) ([][]byte, error) {
	n := len(secret)
	if !belsSize(n) || threshold < 1 || count < threshold || count > 16 {
		return nil, invalid("bels share")
	}
	buf := make([]byte, count*(n+1))
	defer Wipe(buf)
	if e := codeErr("bels share", C.belsShare3(octets(buf), C.size_t(count), C.size_t(threshold), C.size_t(n), octets(secret))); e != nil {
		return nil, e
	}
	out := make([][]byte, count)
	for i := range out {
		out[i] = append([]byte(nil), buf[i*(n+1):(i+1)*(n+1)]...)
	}
	return out, nil
}
func BELSRecoverStandard(shares [][]byte, threshold int) ([]byte, error) {
	if threshold < 1 || len(shares) < threshold || len(shares) > 16 {
		return nil, invalid("bels recover")
	}
	n := len(shares[0]) - 1
	if !belsSize(n) {
		return nil, invalid("bels recover")
	}
	buf := make([]byte, 0, len(shares)*(n+1))
	defer func() { Wipe(buf) }()
	var seen [17]bool
	for _, s := range shares {
		if len(s) != n+1 || s[0] < 1 || s[0] > 16 || seen[s[0]] {
			return nil, invalid("bels recover")
		}
		seen[s[0]] = true
		buf = append(buf, s...)
	}
	out := make([]byte, n)
	if e := codeErr("bels recover", C.belsRecover2(octets(out), C.size_t(len(shares)), C.size_t(n), octets(buf))); e != nil {
		Wipe(out)
		return nil, e
	}
	return out, nil
}

func BELSGenerateCommon(n int, entropy io.Reader) ([]byte, error) {
	if !belsSize(n) {
		return nil, invalid("bels generate common")
	}
	r, e := NewRandom(entropy)
	if e != nil {
		return nil, e
	}
	defer r.Close()
	out := make([]byte, n)
	if e = codeErr("bels generate common", C.belsGenM0(octets(out), C.size_t(n), C.gen_i(C.bee2go_random), r.CTR.s.ptr)); e != nil {
		return nil, e
	}
	return out, nil
}
func BELSGenerateMember(m []byte, entropy io.Reader) ([]byte, error) {
	if err := BELSValidate(m); err != nil {
		return nil, err
	}
	r, e := NewRandom(entropy)
	if e != nil {
		return nil, e
	}
	defer r.Close()
	out := make([]byte, len(m))
	if e = codeErr("bels generate member", C.belsGenMi(octets(out), C.size_t(len(m)), octets(m), C.gen_i(C.bee2go_random), r.CTR.s.ptr)); e != nil {
		return nil, e
	}
	return out, nil
}
func BELSShare(secret, common []byte, members [][]byte, threshold int, entropy io.Reader, standard bool) ([][]byte, error) {
	n := len(secret)
	count := len(members)
	if !belsSize(n) || threshold < 1 || count < threshold || (standard && count > 16) || (!standard && len(common) != n) {
		return nil, invalid("bels share")
	}
	keys := make([]byte, 0, count*n)
	if !standard {
		if err := validateMembers(common, members); err != nil {
			return nil, err
		}
		for _, m := range members {
			keys = append(keys, m...)
		}
	}
	r, e := NewRandom(entropy)
	if e != nil {
		return nil, e
	}
	defer r.Close()
	stride := n
	if standard {
		stride++
	}
	buf := make([]byte, count*stride)
	defer Wipe(buf)
	var code C.err_t
	if standard {
		code = C.belsShare2(octets(buf), C.size_t(count), C.size_t(threshold), C.size_t(n), octets(secret), C.gen_i(C.bee2go_random), r.CTR.s.ptr)
	} else {
		code = C.belsShare(octets(buf), C.size_t(count), C.size_t(threshold), C.size_t(n), octets(secret), octets(common), octets(keys), C.gen_i(C.bee2go_random), r.CTR.s.ptr)
	}
	if e = codeErr("bels share", code); e != nil {
		return nil, e
	}
	out := make([][]byte, count)
	for i := range out {
		out[i] = append([]byte(nil), buf[i*stride:(i+1)*stride]...)
	}
	return out, nil
}
func BELSRecover(shares [][]byte, common []byte, members [][]byte, threshold int) ([]byte, error) {
	n := len(common)
	count := len(shares)
	if !belsSize(n) || threshold < 1 || count < threshold || len(members) != count {
		return nil, invalid("bels recover")
	}
	if err := validateMembers(common, members); err != nil {
		return nil, err
	}
	buf := make([]byte, 0, n*count)
	keys := make([]byte, 0, n*count)
	defer func() { Wipe(buf) }()
	for i, s := range shares {
		if len(s) != n || len(members[i]) != n {
			return nil, invalid("bels recover")
		}
		buf = append(buf, s...)
		keys = append(keys, members[i]...)
	}
	out := make([]byte, n)
	if e := codeErr("bels recover", C.belsRecover(octets(out), C.size_t(count), C.size_t(n), octets(buf), octets(common), octets(keys))); e != nil {
		Wipe(out)
		return nil, e
	}
	return out, nil
}

func validateMembers(common []byte, members [][]byte) error {
	if err := BELSValidate(common); err != nil {
		return err
	}
	for i, m := range members {
		if len(m) != len(common) || bytes.Equal(m, common) {
			return invalid("bels members")
		}
		if err := BELSValidate(m); err != nil {
			return err
		}
		for j := 0; j < i; j++ {
			if bytes.Equal(m, members[j]) {
				return invalid("bels members")
			}
		}
	}
	return nil
}
