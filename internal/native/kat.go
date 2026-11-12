package native

/*
#include "kat_bridge.h"
*/
import "C"

// KATBignKeypair runs the fixed STB test generator.
func KATBignKeypair() ([]byte, []byte, error) {
	a := make([]byte, 32)
	b := make([]byte, 64)
	e := codeErr("selftest.bign", C.bee2go_kat_bign(octets(a), octets(b)))
	if e != nil {
		Wipe(a)
		return nil, nil, e
	}
	return a, b, nil
}

// KATBakeDH applies BAKE DH to the standard base point.
func KATBakeDH(priv []byte) ([]byte, error) {
	if len(priv) != 32 {
		return nil, invalid("selftest.bakeDH")
	}
	out := make([]byte, 64)
	e := codeErr("selftest.bakeDH", C.bee2go_kat_bake_dh(octets(out), octets(priv)))
	if e != nil {
		return nil, e
	}
	return out, nil
}

// KATBPACE returns the fixed-randomness transcript and both session keys.
func KATBPACE(a, b []byte) ([][]byte, error) {
	if len(a) != 48 || len(b) != 48 {
		return nil, invalid("selftest.bpace")
	}
	out := [][]byte{make([]byte, 16), make([]byte, 80), make([]byte, 72), make([]byte, 8), make([]byte, 32), make([]byte, 32)}
	e := codeErr("selftest.bpace", C.bee2go_kat_bpace(octets(out[0]), octets(out[1]), octets(out[2]), octets(out[3]), octets(out[4]), octets(out[5]), octets(a), octets(b)))
	if e != nil {
		for _, v := range out {
			Wipe(v)
		}
		return nil, e
	}
	return out, nil
}
