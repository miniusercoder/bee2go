package native

/*
#include "bake_bridge.h"
*/
import "C"
import (
	"fmt"
	bee2 "github.com/miniusercoder/bee2go/v3"
	"runtime/cgo"
	"unsafe"
)

type CertificateValidator func(paramsDER, cert []byte) ([]byte, error)
type certificateContext struct {
	validator CertificateValidator
	err       error
}

//export bee2go_validate_certificate
func bee2go_validate_certificate(pub *C.octet, p *C.bign_params, data *C.octet, n C.size_t, h C.uintptr_t) (rc C.err_t) {
	ctx := cgo.Handle(h).Value().(*certificateContext)
	defer func() {
		if recover() != nil {
			ctx.err = fmt.Errorf("%w: certificate validator panicked", bee2.ErrAuthentication)
			rc = 514
		}
	}()
	if ctx.validator == nil {
		ctx.err = bee2.ErrAuthentication
		return 514
	}
	var size C.size_t
	if rc = C.bignParamsEnc(nil, &size, p); rc != 0 {
		return rc
	}
	if uint64(size) > uint64(^uint(0)>>1) || uint64(n) > uint64(^uint32(0)>>1) {
		return 109
	}
	der := make([]byte, int(size))
	if rc = C.bignParamsEnc(octets(der), &size, p); rc != 0 {
		return rc
	}
	key, e := ctx.validator(der, C.GoBytes(unsafe.Pointer(data), C.int(n)))
	if e != nil {
		ctx.err = fmt.Errorf("%w: %w", bee2.ErrAuthentication, e)
		return 514
	}
	if len(key) != int(p.l)/2 {
		ctx.err = fmt.Errorf("%w: invalid certificate key length", bee2.ErrAuthentication)
		return 514
	}
	if rc = C.bignPubkeyVal(p, octets(key)); rc != 0 {
		ctx.err = bee2.ErrAuthentication
		return 514
	}
	C.memcpy(unsafe.Pointer(pub), pointer(key), C.size_t(len(key)))
	return 0
}
func certificateCall(v CertificateValidator, fn func(C.uintptr_t) C.err_t) error {
	ctx := &certificateContext{validator: v}
	h := cgo.NewHandle(ctx)
	defer h.Delete()
	rc := fn(C.uintptr_t(h))
	if ctx.err != nil {
		return ctx.err
	}
	return codeErr("certificate operation", rc)
}

type nativeCertificate struct{ data, meta *state }

func newCertificate(data []byte) (*nativeCertificate, error) {
	if len(data) == 0 {
		return nil, invalid("certificate")
	}
	d, e := newState(uintptr(len(data)))
	if e != nil {
		return nil, e
	}
	C.memcpy(d.ptr, pointer(data), C.size_t(len(data)))
	m, e := newState(uintptr(C.sizeof_bake_cert))
	if e != nil {
		d.Close()
		return nil, e
	}
	c := &nativeCertificate{d, m}
	c.c().data = (*C.octet)(d.ptr)
	c.c().len = C.size_t(len(data))
	c.c().val = (C.bake_certval_i)(C.bee2go_certval)
	return c, nil
}
func (c *nativeCertificate) c() *C.bake_cert {
	if c == nil {
		return nil
	}
	return (*C.bake_cert)(c.meta.ptr)
}
func (c *nativeCertificate) Close() {
	if c != nil {
		c.meta.Close()
		c.data.Close()
	}
}
