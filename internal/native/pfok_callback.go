package native

/*
#include "pfok_bridge.h"
*/
import "C"
import (
	"fmt"
	"runtime/cgo"
	"unsafe"
)

type pfokProgress struct {
	fn         func([]byte, uint64)
	panicValue any
}

//export bee2go_pfok_progress
func bee2go_pfok_progress(handle C.uintptr_t, q *C.word, n C.size_t, num C.size_t) {
	p := cgo.Handle(handle).Value().(*pfokProgress)
	if p.panicValue != nil {
		return
	}
	defer func() {
		if v := recover(); v != nil {
			p.panicValue = v
		}
	}()
	p.fn(C.GoBytes(unsafe.Pointer(q), C.int(n*C.size_t(C.sizeof_word))), uint64(num))
}
func PFOKGenProgress(seed PFOKSeed, fn func([]byte, uint64)) (PFOKParams, error) {
	if fn == nil {
		return PFOKGen(seed)
	}
	p := pfokProgress{fn: fn}
	h := cgo.NewHandle(&p)
	defer h.Delete()
	s := pfokSeedC(seed)
	var result C.pfok_params
	e := codeErr("pfok.GenerateWithProgress", C.bee2go_pfok_generate(&result, &s, C.uintptr_t(h)))
	if p.panicValue != nil {
		return PFOKParams{}, fmt.Errorf("pfok progress callback panicked: %v", p.panicValue)
	}
	if e != nil {
		return PFOKParams{}, e
	}
	return pfokParamsGo(result), nil
}
