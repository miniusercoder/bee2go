// Package native is the sole production CGo boundary. Its types are internal.
package native

/*
#cgo CFLAGS: -I${SRCDIR}/../../bee2/include
#cgo LDFLAGS: -L${SRCDIR}/../../build/bee2/src -lbee2_static -lpthread
#include "bridge.h"
#include "build_id.h"
*/
import "C"
