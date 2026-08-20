package bee2go

/*
#cgo CFLAGS: -I${SRCDIR}/bee2/include
#cgo LDFLAGS: -L${SRCDIR}/bee2/build/src -lbee2_static
#include <stdint.h>
#include <stdlib.h>
#include "bee2/core/mem.h"

// mem_wipe_addr accepts the destination as an integer so cgo does not apply
// its recursive Go-pointer check to the surrounding Go allocation. The
// caller passes only the exact byte range to overwrite, pins the allocation
// and keeps it alive until this synchronous call returns.
static void mem_wipe_addr(uintptr_t addr, size_t count) {
	memWipe((void*)addr, count);
}
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

	var pinner runtime.Pinner
	pinner.Pin(unsafe.SliceData(buf))
	defer pinner.Unpin()
	addr := uintptr(unsafe.Pointer(unsafe.SliceData(buf)))
	C.mem_wipe_addr(C.uintptr_t(addr), C.size_t(len(buf)))
	// Keep the Go backing array reachable until the C call has completed.
	runtime.KeepAlive(buf)
}

// freeWiped overwrites an owned C allocation before returning it to malloc.
// Callers must pass the exact allocation size used for ptr.
func freeWiped(ptr unsafe.Pointer, size uintptr) {
	if ptr == nil {
		return
	}
	wipePointer(ptr, size)
	C.free(ptr)
}

func wipePointer(ptr unsafe.Pointer, size uintptr) {
	if ptr != nil && size > 0 {
		C.memWipe(ptr, C.size_t(size))
	}
}
