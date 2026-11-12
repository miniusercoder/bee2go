package native

/*
#include "bridge.h"
#include <bee2/crypto/bign.h>
*/
import "C"
import "io"

func BignIdExtract(p *BignParams, oid, id, sig, pub []byte) ([]byte, []byte, error) {
	if e := p.check(); e != nil {
		return nil, nil, e
	}
	if len(oid) == 0 || len(id) != p.level/4 || len(sig) != 3*p.level/8 || len(pub) != p.level/2 {
		return nil, nil, invalid("bign.identity.extract")
	}
	a, b := make([]byte, p.level/4), make([]byte, p.level/2)
	e := codeErr("bign.identity.extract", C.bignIdExtract(octets(a), octets(b), p.c(), octets(oid), C.size_t(len(oid)), octets(id), octets(sig), octets(pub)))
	if e != nil {
		Wipe(a)
		Wipe(b)
		return nil, nil, e
	}
	return a, b, nil
}
func BignIdSign(p *BignParams, oid, id, h, a []byte, r io.Reader) ([]byte, error) {
	if e := bignSignCheck(p, oid, h, a); e != nil {
		return nil, e
	}
	if len(id) != p.level/4 {
		return nil, invalid("bign.identity.sign")
	}
	rng, e := NewRandom(r)
	if e != nil {
		return nil, e
	}
	defer rng.Close()
	sig := make([]byte, 3*p.level/8)
	e = codeErr("bign.identity.sign", C.bignIdSign(octets(sig), p.c(), octets(oid), C.size_t(len(oid)), octets(id), octets(h), octets(a), (C.gen_i)(C.bee2go_random), rng.CTR.s.ptr))
	if e != nil {
		Wipe(sig)
		return nil, e
	}
	return sig, nil
}
func BignIdSign2(p *BignParams, oid, id, h, a, t []byte) ([]byte, error) {
	if e := bignSignCheck(p, oid, h, a); e != nil {
		return nil, e
	}
	if len(id) != p.level/4 {
		return nil, invalid("bign.identity.sign2")
	}
	sig := make([]byte, 3*p.level/8)
	e := codeErr("bign.identity.sign2", C.bignIdSign2(octets(sig), p.c(), octets(oid), C.size_t(len(oid)), octets(id), octets(h), octets(a), pointer(t), C.size_t(len(t))))
	if e != nil {
		Wipe(sig)
		return nil, e
	}
	return sig, nil
}
func BignIdVerify(p *BignParams, oid, id, h, sig, idpub, pub []byte) error {
	if e := p.check(); e != nil {
		return e
	}
	if len(oid) == 0 || len(id) != p.level/4 || len(h) != p.level/4 || len(sig) != 3*p.level/8 || len(idpub) != p.level/2 || len(pub) != p.level/2 {
		return invalid("bign.identity.verify")
	}
	return codeErr("bign.identity.verify", C.bignIdVerify(p.c(), octets(oid), C.size_t(len(oid)), octets(id), octets(h), octets(sig), octets(idpub), octets(pub)))
}
