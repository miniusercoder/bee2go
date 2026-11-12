// Package brng implements the bee2 CTR and HMAC pseudorandom generators.
// Never reuse a key and IV pair. Objects require caller synchronization.
package brng

import (
	"github.com/miniusercoder/bee2go/v3/internal/native"
)

type CTR struct{ n *native.CTR }

func NewCTR(key, iv []byte) (*CTR, error) {
	s, e := native.NewCTR(key, iv)
	if e != nil {
		return nil, e
	}
	return &CTR{s}, nil
}
func (r *CTR) Read(b []byte) (int, error) { return r.n.Read(b) }
func (r *CTR) Transform(b []byte) error   { return r.n.Transform(b) }

// IV exports the updated IV. Resume only at a full 32-byte block boundary;
// a partial block has buffered bytes which the IV does not encode.
func (r *CTR) IV() ([]byte, error) { return r.n.IV() }
func (r *CTR) Close() error {
	if r == nil {
		return nil
	}
	return r.n.Close()
}
func CTRRand(count int, key, iv []byte) (out, next []byte, err error) {
	if count < 0 {
		return nil, nil, nativeInputError()
	}
	r, e := NewCTR(key, iv)
	if e != nil {
		return nil, nil, e
	}
	defer r.Close()
	out = make([]byte, count)
	r.Read(out)
	next, err = r.IV()
	return
}
func CTRTransform(buf, key, iv []byte) ([]byte, error) {
	r, e := NewCTR(key, iv)
	if e != nil {
		return nil, e
	}
	defer r.Close()
	if e = r.Transform(buf); e != nil {
		return nil, e
	}
	return r.IV()
}

type HMAC struct{ n *native.HMAC }

func NewHMAC(key, iv []byte) (*HMAC, error) {
	s, e := native.NewHMAC(key, iv)
	if e != nil {
		return nil, e
	}
	return &HMAC{s}, nil
}
func (r *HMAC) Read(b []byte) (int, error) { return r.n.Read(b) }
func (r *HMAC) Close() error {
	if r == nil {
		return nil
	}
	return r.n.Close()
}
func HMACRand(count int, key, iv []byte) ([]byte, error) {
	if count < 0 {
		return nil, nativeInputError()
	}
	r, e := NewHMAC(key, iv)
	if e != nil {
		return nil, e
	}
	defer r.Close()
	out := make([]byte, count)
	_, e = r.Read(out)
	return out, e
}
