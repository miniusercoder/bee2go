package native

/*
#include "bridge.h"
#include <bee2/crypto/belt.h>
static void go_belt_block(octet *dst, const octet *src, const u32 *key, int decrypt) { u32 block[4]; memcpy(block, src, 16); if (decrypt) beltBlockDecr((octet*)block, key); else beltBlockEncr((octet*)block, key); memcpy(dst, block, 16); memWipe(block, 16); }
*/
import "C"
import "unsafe"
import bee2 "github.com/miniusercoder/bee2go/v3"

type BeltHash struct{ s *state }

func NewBeltHash() (*BeltHash, error) {
	s, e := newState(uintptr(C.beltHash_keep()))
	if e != nil {
		return nil, e
	}
	C.beltHashStart(s.ptr)
	return &BeltHash{s}, nil
}
func (h *BeltHash) Write(p []byte) (int, error) {
	if e := h.s.check(); e != nil {
		return 0, e
	}
	if len(p) > 0 {
		C.beltHashStepH(pointer(p), C.size_t(len(p)), h.s.ptr)
	}
	return len(p), nil
}
func (h *BeltHash) Sum(b []byte) []byte {
	if e := h.s.check(); e != nil {
		panic(e)
	}
	out := make([]byte, 32)
	C.beltHashStepG(octets(out), h.s.ptr)
	return append(b, out...)
}
func (h *BeltHash) Reset() {
	if e := h.s.check(); e != nil {
		panic(e)
	}
	C.memWipe(h.s.ptr, C.size_t(h.s.size))
	C.beltHashStart(h.s.ptr)
}
func (h *BeltHash) Size() int {
	if e := h.s.check(); e != nil {
		panic(e)
	}
	return 32
}
func (h *BeltHash) BlockSize() int {
	if e := h.s.check(); e != nil {
		panic(e)
	}
	return 32
}
func (h *BeltHash) Close() error {
	if h == nil {
		return nil
	}
	return h.s.Close()
}

type BeltBlock struct{ s *state }

func NewBeltBlock(key []byte) (*BeltBlock, error) {
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return nil, invalid("belt.NewBlock")
	}
	s, e := newState(32)
	if e != nil {
		return nil, e
	}
	C.beltKeyExpand2((*C.u32)(s.ptr), octets(key), C.size_t(len(key)))
	return &BeltBlock{s}, nil
}
func (b *BeltBlock) Crypt(dst, src []byte, decrypt bool) {
	if e := b.s.check(); e != nil {
		panic(e)
	}
	if len(src) < 16 || len(dst) < 16 {
		panic("belt: short block")
	}
	a, c := uintptr(unsafe.Pointer(&dst[0])), uintptr(unsafe.Pointer(&src[0]))
	if a != c && a < c+16 && c < a+16 {
		panic("belt: invalid buffer overlap")
	}
	d := C.int(0)
	if decrypt {
		d = 1
	}
	C.go_belt_block(octets(dst), octets(src), (*C.u32)(b.s.ptr), d)
}
func (b *BeltBlock) Close() error {
	if b == nil {
		return nil
	}
	return b.s.Close()
}

func beltKeyOK(key []byte) bool { return len(key) == 16 || len(key) == 24 || len(key) == 32 }
func BeltMode(mode int, decrypt bool, src, key, iv []byte) ([]byte, error) {
	if !beltKeyOK(key) || (mode != 0 && len(iv) != 16) || ((mode == 0 || mode == 1) && len(src) < 16) {
		return nil, invalid("belt.mode")
	}
	out := make([]byte, len(src))
	var rc C.err_t
	switch mode {
	case 0:
		if decrypt {
			rc = C.beltECBDecr(pointer(out), pointer(src), C.size_t(len(src)), octets(key), C.size_t(len(key)))
		} else {
			rc = C.beltECBEncr(pointer(out), pointer(src), C.size_t(len(src)), octets(key), C.size_t(len(key)))
		}
	case 1:
		if decrypt {
			rc = C.beltCBCDecr(pointer(out), pointer(src), C.size_t(len(src)), octets(key), C.size_t(len(key)), octets(iv))
		} else {
			rc = C.beltCBCEncr(pointer(out), pointer(src), C.size_t(len(src)), octets(key), C.size_t(len(key)), octets(iv))
		}
	case 2:
		if decrypt {
			rc = C.beltCFBDecr(pointer(out), pointer(src), C.size_t(len(src)), octets(key), C.size_t(len(key)), octets(iv))
		} else {
			rc = C.beltCFBEncr(pointer(out), pointer(src), C.size_t(len(src)), octets(key), C.size_t(len(key)), octets(iv))
		}
	case 3:
		rc = C.beltCTR(pointer(out), pointer(src), C.size_t(len(src)), octets(key), C.size_t(len(key)), octets(iv))
	default:
		return nil, invalid("belt.mode")
	}
	if e := codeErr("belt.mode", rc); e != nil {
		Wipe(out)
		return nil, e
	}
	return out, nil
}
func BeltAEAD(che, open bool, src, aad, tag, key, iv []byte) ([]byte, []byte, error) {
	if !beltKeyOK(key) || len(iv) != 16 || (open && len(tag) != 8) {
		return nil, nil, invalid("belt.aead")
	}
	out := make([]byte, len(src))
	if !open {
		tag = make([]byte, 8)
	}
	var rc C.err_t
	if che {
		if open {
			rc = C.beltCHEUnwrap(pointer(out), pointer(src), C.size_t(len(src)), pointer(aad), C.size_t(len(aad)), octets(tag), octets(key), C.size_t(len(key)), octets(iv))
		} else {
			rc = C.beltCHEWrap(pointer(out), octets(tag), pointer(src), C.size_t(len(src)), pointer(aad), C.size_t(len(aad)), octets(key), C.size_t(len(key)), octets(iv))
		}
	} else {
		if open {
			rc = C.beltDWPUnwrap(pointer(out), pointer(src), C.size_t(len(src)), pointer(aad), C.size_t(len(aad)), octets(tag), octets(key), C.size_t(len(key)), octets(iv))
		} else {
			rc = C.beltDWPWrap(pointer(out), octets(tag), pointer(src), C.size_t(len(src)), pointer(aad), C.size_t(len(aad)), octets(key), C.size_t(len(key)), octets(iv))
		}
	}
	if e := codeErr("belt.aead", rc); e != nil {
		Wipe(out)
		return nil, nil, e
	}
	return out, tag, nil
}
func BeltDisk(sector, decrypt bool, src, key, iv []byte) ([]byte, error) {
	if !beltKeyOK(key) || len(iv) != 16 || len(src)%16 != 0 || len(src) < 16 || (sector && len(src) < 32) {
		return nil, invalid("belt.disk")
	}
	out := make([]byte, len(src))
	var rc C.err_t
	if sector {
		if decrypt {
			rc = C.beltSDEDecr(pointer(out), pointer(src), C.size_t(len(src)), octets(key), C.size_t(len(key)), octets(iv))
		} else {
			rc = C.beltSDEEncr(pointer(out), pointer(src), C.size_t(len(src)), octets(key), C.size_t(len(key)), octets(iv))
		}
	} else {
		if decrypt {
			rc = C.beltBDEDecr(pointer(out), pointer(src), C.size_t(len(src)), octets(key), C.size_t(len(key)), octets(iv))
		} else {
			rc = C.beltBDEEncr(pointer(out), pointer(src), C.size_t(len(src)), octets(key), C.size_t(len(key)), octets(iv))
		}
	}
	if e := codeErr("belt.disk", rc); e != nil {
		Wipe(out)
		return nil, e
	}
	return out, nil
}
func BeltFMT(decrypt bool, src []uint16, mod uint32, key, iv []byte) ([]uint16, error) {
	if mod < 2 || mod > 65536 || len(src) < 2 || len(src) > 600 || !beltKeyOK(key) || (len(iv) != 0 && len(iv) != 16) {
		return nil, invalid("belt.FMT")
	}
	for _, v := range src {
		if uint32(v) >= mod {
			return nil, invalid("belt.FMT")
		}
	}
	out := make([]uint16, len(src))
	var rc C.err_t
	if decrypt {
		rc = C.beltFMTDecr((*C.u16)(unsafe.Pointer(&out[0])), C.u32(mod), (*C.u16)(unsafe.Pointer(&src[0])), C.size_t(len(src)), octets(key), C.size_t(len(key)), octets(iv))
	} else {
		rc = C.beltFMTEncr((*C.u16)(unsafe.Pointer(&out[0])), C.u32(mod), (*C.u16)(unsafe.Pointer(&src[0])), C.size_t(len(src)), octets(key), C.size_t(len(key)), octets(iv))
	}
	if e := codeErr("belt.FMT", rc); e != nil {
		clear(out)
		return nil, e
	}
	return out, nil
}
func BeltMAC(hmac bool, src, key []byte) ([]byte, error) {
	if !hmac && !beltKeyOK(key) {
		return nil, invalid("belt.MAC")
	}
	n := 8
	if hmac {
		n = 32
	}
	out := make([]byte, n)
	var rc C.err_t
	if hmac {
		rc = C.beltHMAC(octets(out), pointer(src), C.size_t(len(src)), octets(key), C.size_t(len(key)))
	} else {
		rc = C.beltMAC(octets(out), pointer(src), C.size_t(len(src)), octets(key), C.size_t(len(key)))
	}
	if e := codeErr("belt.MAC", rc); e != nil {
		Wipe(out)
		return nil, e
	}
	return out, nil
}
func BeltKRP(src, level, header []byte, n int) ([]byte, error) {
	if !beltKeyOK(src) || (n != 16 && n != 24 && n != 32) || n > len(src) || len(level) != 12 || len(header) != 16 {
		return nil, invalid("belt.KRP")
	}
	out := make([]byte, n)
	e := codeErr("belt.KRP", C.beltKRP(octets(out), C.size_t(n), octets(src), C.size_t(len(src)), octets(level), octets(header)))
	if e != nil {
		Wipe(out)
		return nil, e
	}
	return out, nil
}
func BeltPBKDF2(password []byte, iter int, salt []byte) ([]byte, error) {
	if iter <= 0 {
		return nil, invalid("belt.PBKDF2")
	}
	out := make([]byte, 32)
	e := codeErr("belt.PBKDF2", C.beltPBKDF2(octets(out), octets(password), C.size_t(len(password)), C.size_t(iter), octets(salt), C.size_t(len(salt))))
	if e != nil {
		Wipe(out)
		return nil, e
	}
	return out, nil
}
func BeltKWP(open bool, src, header, key []byte) ([]byte, error) {
	if !beltKeyOK(key) || (len(header) != 0 && len(header) != 16) || (!open && len(src) < 16) || (open && len(src) < 32) {
		return nil, invalid("belt.KWP")
	}
	n := len(src) + 16
	if open {
		n = len(src) - 16
	}
	out := make([]byte, n)
	var rc C.err_t
	if open {
		rc = C.beltKWPUnwrap(octets(out), octets(src), C.size_t(len(src)), octets(header), octets(key), C.size_t(len(key)))
	} else {
		rc = C.beltKWPWrap(octets(out), octets(src), C.size_t(len(src)), octets(header), octets(key), C.size_t(len(key)))
	}
	if e := codeErr("belt.KWP", rc); e != nil {
		Wipe(out)
		return nil, e
	}
	return out, nil
}

type BeltWBL struct{ s *state }

func NewBeltWBL(key []byte) (*BeltWBL, error) {
	if !beltKeyOK(key) {
		return nil, invalid("belt.WBL")
	}
	s, e := newState(uintptr(C.beltWBL_keep()))
	if e != nil {
		return nil, e
	}
	C.beltWBLStart(s.ptr, octets(key), C.size_t(len(key)))
	return &BeltWBL{s}, nil
}
func (w *BeltWBL) Crypt(b []byte, mode int) error {
	if e := w.s.check(); e != nil {
		return e
	}
	if len(b) < 32 {
		return invalid("belt.WBL")
	}
	switch mode {
	case 0:
		C.beltWBLStepE(pointer(b), C.size_t(len(b)), w.s.ptr)
	case 1:
		C.beltWBLStepD(pointer(b), C.size_t(len(b)), w.s.ptr)
	case 2:
		C.beltWBLStepR(pointer(b), C.size_t(len(b)), w.s.ptr)
	default:
		return invalid("belt.WBL")
	}
	return nil
}
func (w *BeltWBL) Close() error {
	if w == nil {
		return nil
	}
	return w.s.Close()
}

type BeltMACState struct {
	s, initial *state
	hmac       bool
}

func NewBeltMAC(hmac bool, key []byte) (*BeltMACState, error) {
	if !hmac && !beltKeyOK(key) {
		return nil, invalid("belt.NewMAC")
	}
	size := uintptr(C.beltMAC_keep())
	if hmac {
		size = uintptr(C.beltHMAC_keep())
	}
	s, e := newState(size)
	if e != nil {
		return nil, e
	}
	initial, e := newState(size)
	if e != nil {
		s.Close()
		return nil, e
	}
	if hmac {
		C.beltHMACStart(s.ptr, octets(key), C.size_t(len(key)))
	} else {
		C.beltMACStart(s.ptr, octets(key), C.size_t(len(key)))
	}
	C.memcpy(initial.ptr, s.ptr, C.size_t(size))
	return &BeltMACState{s, initial, hmac}, nil
}
func (m *BeltMACState) Write(b []byte) (int, error) {
	if e := m.s.check(); e != nil {
		return 0, e
	}
	if len(b) > 0 {
		if m.hmac {
			C.beltHMACStepA(pointer(b), C.size_t(len(b)), m.s.ptr)
		} else {
			C.beltMACStepA(pointer(b), C.size_t(len(b)), m.s.ptr)
		}
	}
	return len(b), nil
}
func (m *BeltMACState) Size() int {
	if e := m.s.check(); e != nil {
		panic(e)
	}
	if m.hmac {
		return 32
	}
	return 8
}
func (m *BeltMACState) BlockSize() int {
	if e := m.s.check(); e != nil {
		panic(e)
	}
	if m.hmac {
		return 32
	}
	return 16
}
func (m *BeltMACState) Sum(b []byte) []byte {
	if e := m.s.check(); e != nil {
		panic(e)
	}
	out := make([]byte, m.Size())
	if m.hmac {
		C.beltHMACStepG(octets(out), m.s.ptr)
	} else {
		C.beltMACStepG(octets(out), m.s.ptr)
	}
	return append(b, out...)
}
func (m *BeltMACState) Reset() {
	if e := m.s.check(); e != nil {
		panic(e)
	}
	C.memcpy(m.s.ptr, m.initial.ptr, C.size_t(m.s.size))
}
func (m *BeltMACState) Close() error {
	if m == nil {
		return nil
	}
	m.s.Close()
	return m.initial.Close()
}

type BeltStream struct {
	s              *state
	mode           int
	decrypt, final bool
}

func NewBeltStream(mode int, key, iv []byte, decrypt bool) (*BeltStream, error) {
	if !beltKeyOK(key) || (mode != 0 && len(iv) != 16) {
		return nil, invalid("belt.stream")
	}
	var size uintptr
	switch mode {
	case 0:
		size = uintptr(C.beltECB_keep())
	case 1:
		size = uintptr(C.beltCBC_keep())
	case 2:
		size = uintptr(C.beltCFB_keep())
	case 3:
		size = uintptr(C.beltCTR_keep())
	case 4:
		size = uintptr(C.beltBDE_keep())
	default:
		return nil, invalid("belt.stream")
	}
	s, e := newState(size)
	if e != nil {
		return nil, e
	}
	switch mode {
	case 0:
		C.beltECBStart(s.ptr, octets(key), C.size_t(len(key)))
	case 1:
		C.beltCBCStart(s.ptr, octets(key), C.size_t(len(key)), octets(iv))
	case 2:
		C.beltCFBStart(s.ptr, octets(key), C.size_t(len(key)), octets(iv))
	case 3:
		C.beltCTRStart(s.ptr, octets(key), C.size_t(len(key)), octets(iv))
	case 4:
		C.beltBDEStart(s.ptr, octets(key), C.size_t(len(key)), octets(iv))
	}
	return &BeltStream{s: s, mode: mode, decrypt: decrypt}, nil
}
func (s *BeltStream) Refresh(iv []byte) error {
	if e := s.s.check(); e != nil {
		return e
	}
	if len(iv) != 16 || s.mode == 0 {
		return invalid("belt.Refresh")
	}
	switch s.mode {
	case 1:
		C.beltCBCRefresh(s.s.ptr, octets(iv))
	case 2:
		C.beltCFBRefresh(s.s.ptr, octets(iv))
	case 3:
		C.beltCTRRefresh(s.s.ptr, octets(iv))
	case 4:
		C.beltBDERefresh(s.s.ptr, octets(iv))
	}
	s.final = false
	return nil
}
func (s *BeltStream) Crypt(b []byte, final bool) error {
	if e := s.s.check(); e != nil {
		return e
	}
	if s.final {
		return bee2.ErrState
	}
	if s.mode == 0 || s.mode == 1 {
		if (final && len(b) < 16) || (!final && len(b)%16 != 0) {
			return invalid("belt.stream")
		}
	}
	if s.mode == 4 && len(b)%16 != 0 {
		return invalid("belt.stream")
	}
	if len(b) > 0 {
		switch s.mode {
		case 0:
			if s.decrypt {
				C.beltECBStepD(pointer(b), C.size_t(len(b)), s.s.ptr)
			} else {
				C.beltECBStepE(pointer(b), C.size_t(len(b)), s.s.ptr)
			}
		case 1:
			if s.decrypt {
				C.beltCBCStepD(pointer(b), C.size_t(len(b)), s.s.ptr)
			} else {
				C.beltCBCStepE(pointer(b), C.size_t(len(b)), s.s.ptr)
			}
		case 2:
			if s.decrypt {
				C.beltCFBStepD(pointer(b), C.size_t(len(b)), s.s.ptr)
			} else {
				C.beltCFBStepE(pointer(b), C.size_t(len(b)), s.s.ptr)
			}
		case 3:
			C.beltCTRStepE(pointer(b), C.size_t(len(b)), s.s.ptr)
		case 4:
			if s.decrypt {
				C.beltBDEStepD(pointer(b), C.size_t(len(b)), s.s.ptr)
			} else {
				C.beltBDEStepE(pointer(b), C.size_t(len(b)), s.s.ptr)
			}
		}
	}
	s.final = final
	return nil
}
func (s *BeltStream) Close() error {
	if s == nil {
		return nil
	}
	return s.s.Close()
}

type BeltSDE struct{ s *state }

func NewBeltSDE(key []byte) (*BeltSDE, error) {
	if !beltKeyOK(key) {
		return nil, invalid("belt.SDE")
	}
	s, e := newState(uintptr(C.beltSDE_keep()))
	if e != nil {
		return nil, e
	}
	C.beltSDEStart(s.ptr, octets(key), C.size_t(len(key)))
	return &BeltSDE{s}, nil
}
func (s *BeltSDE) Crypt(b, iv []byte, decrypt bool) error {
	if e := s.s.check(); e != nil {
		return e
	}
	if len(b) < 32 || len(b)%16 != 0 || len(iv) != 16 {
		return invalid("belt.SDE")
	}
	if decrypt {
		C.beltSDEStepD(pointer(b), C.size_t(len(b)), octets(iv), s.s.ptr)
	} else {
		C.beltSDEStepE(pointer(b), C.size_t(len(b)), octets(iv), s.s.ptr)
	}
	return nil
}
func (s *BeltSDE) Close() error {
	if s == nil {
		return nil
	}
	return s.s.Close()
}

type BeltFMTState struct {
	s     *state
	mod   uint32
	count int
}

func NewBeltFMT(mod uint32, count int, key []byte) (*BeltFMTState, error) {
	if mod < 2 || mod > 65536 || count < 2 || count > 600 || !beltKeyOK(key) {
		return nil, invalid("belt.FMT")
	}
	s, e := newState(uintptr(C.beltFMT_keep(C.u32(mod), C.size_t(count))))
	if e != nil {
		return nil, e
	}
	C.beltFMTStart(s.ptr, C.u32(mod), C.size_t(count), octets(key), C.size_t(len(key)))
	return &BeltFMTState{s, mod, count}, nil
}
func (f *BeltFMTState) Crypt(b []uint16, iv []byte, decrypt bool) error {
	if e := f.s.check(); e != nil {
		return e
	}
	if len(b) != f.count || (len(iv) != 0 && len(iv) != 16) {
		return invalid("belt.FMT")
	}
	for _, v := range b {
		if uint32(v) >= f.mod {
			return invalid("belt.FMT")
		}
	}
	if decrypt {
		C.beltFMTStepD((*C.u16)(unsafe.Pointer(&b[0])), octets(iv), f.s.ptr)
	} else {
		C.beltFMTStepE((*C.u16)(unsafe.Pointer(&b[0])), octets(iv), f.s.ptr)
	}
	return nil
}
func (f *BeltFMTState) Close() error {
	if f == nil {
		return nil
	}
	return f.s.Close()
}

type BeltKRPState struct {
	s *state
	n int
}

func NewBeltKRP(src, level []byte) (*BeltKRPState, error) {
	if !beltKeyOK(src) || len(level) != 12 {
		return nil, invalid("belt.KRP")
	}
	s, e := newState(uintptr(C.beltKRP_keep()))
	if e != nil {
		return nil, e
	}
	C.beltKRPStart(s.ptr, octets(src), C.size_t(len(src)), octets(level))
	return &BeltKRPState{s, len(src)}, nil
}
func (k *BeltKRPState) Derive(n int, header []byte) ([]byte, error) {
	if e := k.s.check(); e != nil {
		return nil, e
	}
	if (n != 16 && n != 24 && n != 32) || n > k.n || len(header) != 16 {
		return nil, invalid("belt.KRP")
	}
	out := make([]byte, n)
	C.beltKRPStepG(octets(out), C.size_t(n), octets(header), k.s.ptr)
	return out, nil
}
func (k *BeltKRPState) Close() error {
	if k == nil {
		return nil
	}
	return k.s.Close()
}

func (b *BeltBlock) BlockSize() int {
	if e := b.s.check(); e != nil {
		panic(e)
	}
	return 16
}
func (w *BeltWBL) DecryptSplit(first, last []byte) error {
	if e := w.s.check(); e != nil {
		return e
	}
	if len(first) < 16 || len(last) != 16 {
		return invalid("belt.WBL.DecryptSplit")
	}
	a, b := uintptr(pointer(first)), uintptr(pointer(last))
	if a < b+uintptr(len(last)) && b < a+uintptr(len(first)) {
		return invalid("belt.WBL.DecryptSplit")
	}
	C.beltWBLStepD2(pointer(first), pointer(last), C.size_t(len(first)+len(last)), w.s.ptr)
	return nil
}
