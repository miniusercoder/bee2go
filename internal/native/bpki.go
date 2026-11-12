package native

/*
#include "bridge.h"
#include <bee2/crypto/bpki.h>
*/
import "C"

func BPKIWrap(secret, pwd, salt []byte, iter int, share bool) ([]byte, error) {
	const op = "bpki wrap"
	if len(salt) != 8 || iter < 10000 {
		return nil, invalid(op)
	}
	if share {
		if (len(secret) != 17 && len(secret) != 25 && len(secret) != 33) || secret[0] < 1 || secret[0] > 16 {
			return nil, invalid(op)
		}
	} else if len(secret) != 24 && len(secret) != 32 && len(secret) != 48 && len(secret) != 64 {
		return nil, invalid(op)
	}
	var n C.size_t
	call := func(out []byte) C.err_t {
		if share {
			return C.bpkiShareWrap(octets(out), &n, octets(secret), C.size_t(len(secret)), octets(pwd), C.size_t(len(pwd)), octets(salt), C.size_t(iter))
		}
		return C.bpkiPrivkeyWrap(octets(out), &n, octets(secret), C.size_t(len(secret)), octets(pwd), C.size_t(len(pwd)), octets(salt), C.size_t(iter))
	}
	if err := codeErr(op, call(nil)); err != nil {
		return nil, err
	}
	if n == 0 || uint64(n) > 1024 {
		return nil, invalid(op)
	}
	out := make([]byte, int(n))
	capacity := n
	if err := codeErr(op, call(out)); err != nil {
		Wipe(out)
		return nil, err
	}
	if n != capacity {
		Wipe(out)
		return nil, invalid(op)
	}
	return out, nil
}
func BPKIUnwrap(der, pwd []byte, share bool) ([]byte, error) {
	const op = "bpki unwrap"
	if len(der) == 0 {
		return nil, invalid(op)
	}
	out := make([]byte, 64)
	var n C.size_t
	var code C.err_t
	if share {
		code = C.bpkiShareUnwrap(octets(out), &n, octets(der), C.size_t(len(der)), octets(pwd), C.size_t(len(pwd)))
	} else {
		code = C.bpkiPrivkeyUnwrap(octets(out), &n, octets(der), C.size_t(len(der)), octets(pwd), C.size_t(len(pwd)))
	}
	if err := codeErr(op, code); err != nil {
		Wipe(out)
		return nil, err
	}
	if n > 64 {
		Wipe(out)
		return nil, invalid(op)
	}
	return out[:int(n)], nil
}
func BPKIRewrapCSR(csr, key []byte) ([]byte, error) {
	const op = "bpki CSR rewrap"
	if len(csr) == 0 || len(key) != 32 {
		return nil, invalid(op)
	}
	out := append([]byte(nil), csr...)
	if err := codeErr(op, C.bpkiCSRRewrap(octets(out), C.size_t(len(out)), octets(key), C.size_t(len(key)))); err != nil {
		return nil, err
	}
	return out, nil
}
func BPKIUnwrapCSR(csr []byte) ([]byte, error) {
	const op = "bpki CSR unwrap"
	if len(csr) == 0 {
		return nil, invalid(op)
	}
	out := make([]byte, 64)
	var n C.size_t
	if err := codeErr(op, C.bpkiCSRUnwrap(octets(out), &n, octets(csr), C.size_t(len(csr)))); err != nil {
		return nil, err
	}
	if n != 64 {
		return nil, invalid(op)
	}
	return out, nil
}
