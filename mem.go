package bee2go

/*
#cgo CFLAGS: -I${SRCDIR}/bee2/include
#cgo LDFLAGS: -L${SRCDIR}/bee2/build/src -lbee2_static
#include "bee2/core/mem.h"
*/
import "C"

import (
	"runtime"
	"unsafe"
)

// MemWipe securely overwrites buf using bee2's memWipe implementation.
//
// The replacement byte values are unspecified. MemWipe only overwrites the
// bytes in the slice's current length; it cannot erase copies of those bytes
// made elsewhere by Go or by the caller. To wipe a slice's full capacity, the
// caller must first reslice it to that capacity.
//
// MemWipe is safe to call with a nil or empty slice. The caller must
// synchronize concurrent access to buf.
func MemWipe(buf []byte) {
	if len(buf) == 0 {
		return
	}

	C.memWipe(unsafe.Pointer(unsafe.SliceData(buf)), C.size_t(len(buf)))
	// Keep the Go backing array reachable until the C call has completed.
	runtime.KeepAlive(buf)
}
