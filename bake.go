package bee2go

/*
#cgo CFLAGS: -I${SRCDIR}/bee2/include
#cgo LDFLAGS: -L${SRCDIR}/bee2/build/src -lbee2_static
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "bee2/core/err.h"
#include "bee2/crypto/bake.h"
#include "bee2/crypto/bign.h"

// CGO cannot cast unsafe.Pointer to a C function-pointer type directly.
// These thin wrappers accept void* and perform the cast in C, where it is valid.

static void bake_settings_set_rng(bake_settings* s, void* rng_fn, void* rng_state) {
	s->rng = (gen_i)rng_fn;
	s->rng_state = rng_state;
}

static bake_cert* make_bake_cert(octet* data, size_t len, void* val_fn) {
	bake_cert* c = (bake_cert*)malloc(sizeof(bake_cert));
	if (c) {
		c->data = data;
		c->len  = len;
		c->val  = (bake_certval_i)val_fn;
	}
	return c;
}

static err_t bsts_step4_wrap(
	octet* out, const octet* in, size_t in_len, void* vala, void* state)
{
	return bakeBSTSStep4(out, in, in_len, (bake_certval_i)vala, state);
}

static err_t bsts_step5_wrap(
	const octet* in, size_t in_len, void* valb, void* state)
{
	return bakeBSTSStep5(in, in_len, (bake_certval_i)valb, state);
}

// bake_urandom is a gen_i that reads random bytes from /dev/urandom.
static void bake_urandom(void* buf, size_t count, void* state) {
	FILE* f = fopen("/dev/urandom", "rb");
	if (f) { fread(buf, 1, count, f); fclose(f); }
}

// accept_all_certval is a bake_certval_i that accepts any certificate whose
// last l/2 bytes are treated as the public key. Convention: cert data is
// <identity_bytes> || <pubkey_bytes>, so pubkey = data[len - l/2 : len].
static err_t accept_all_certval(
	octet* pubkey, const bign_params* params,
	const octet* data, size_t len)
{
	if (!params || (params->l != 128 && params->l != 192 && params->l != 256))
		return ERR_BAD_INPUT;
	if (!data || len < params->l / 2)
		return ERR_BAD_CERT;
	if (pubkey)
		memcpy(pubkey, data + (len - params->l / 2), params->l / 2);
	return ERR_OK;
}

// Getter helpers return void* so CGO can map them to unsafe.Pointer.
static void* get_bake_urandom(void)     { return (void*)bake_urandom; }
static void* get_accept_all_certval(void) { return (void*)accept_all_certval; }
*/
import "C"
import (
	"errors"
	"unsafe"
)

// ────────────────────────────────────────────────────────────────────────────
// Built-in C helpers exposed to Go callers
// ────────────────────────────────────────────────────────────────────────────

// BakeDefaultRNG returns the /dev/urandom gen_i function pointer as
// unsafe.Pointer, suitable for passing to NewBakeSettings.
func BakeDefaultRNG() unsafe.Pointer { return C.get_bake_urandom() }

// BakeAcceptAllCertVal returns a bake_certval_i function pointer as
// unsafe.Pointer that accepts any certificate and extracts the public key from
// its last l/2 bytes (convention: cert = <identity> || <pubkey>).
// Suitable for passing to NewBakeCert, Step4, and Step5.
func BakeAcceptAllCertVal() unsafe.Pointer { return C.get_accept_all_certval() }

// ────────────────────────────────────────────────────────────────────────────
// BakeSettings
// ────────────────────────────────────────────────────────────────────────────

// BakeSettings wraps bake_settings.
// rng must be a C gen_i function pointer cast to unsafe.Pointer (CGo cannot
// convert a Go func to a C function pointer directly).
// rngState is the opaque state pointer passed back to rng on each call.
type BakeSettings struct {
	settings *C.bake_settings
	helloa   unsafe.Pointer
	hellob   unsafe.Pointer
}

// NewBakeSettings allocates and populates a bake_settings struct.
// helloa / hellob are optional greeting messages; pass nil to omit.
func NewBakeSettings(kca, kcb bool, helloa, hellob []byte, rng, rngState unsafe.Pointer) (*BakeSettings, error) {
	s := (*C.bake_settings)(C.calloc(1, C.size_t(C.sizeof_bake_settings)))
	if s == nil {
		return nil, errors.New("bee2: failed to allocate bake_settings")
	}
	bs := &BakeSettings{settings: s}

	if kca {
		s.kca = 1
	}
	if kcb {
		s.kcb = 1
	}
	if len(helloa) > 0 {
		bs.helloa = C.CBytes(helloa)
		s.helloa = bs.helloa
		s.helloa_len = C.size_t(len(helloa))
	}
	if len(hellob) > 0 {
		bs.hellob = C.CBytes(hellob)
		s.hellob = bs.hellob
		s.hellob_len = C.size_t(len(hellob))
	}
	if rng != nil {
		C.bake_settings_set_rng(s, rng, rngState)
	}
	return bs, nil
}

// Free releases C memory owned by BakeSettings.
func (s *BakeSettings) Free() {
	if s.helloa != nil {
		C.free(s.helloa)
		s.helloa = nil
	}
	if s.hellob != nil {
		C.free(s.hellob)
		s.hellob = nil
	}
	if s.settings != nil {
		C.free(unsafe.Pointer(s.settings))
		s.settings = nil
	}
}

// ────────────────────────────────────────────────────────────────────────────
// BakeCert
// ────────────────────────────────────────────────────────────────────────────

// BakeCert wraps bake_cert.
type BakeCert struct {
	cert  *C.bake_cert
	data  unsafe.Pointer
	owned bool
}

// NewBakeCert creates a BakeCert from raw certificate data and a C-side
// validation function pointer (bake_certval_i cast to unsafe.Pointer).
// Pass nil for valFn to skip validation.
func NewBakeCert(data []byte, valFn unsafe.Pointer) (*BakeCert, error) {
	cData := C.CBytes(data)
	cert := C.make_bake_cert((*C.octet)(cData), C.size_t(len(data)), valFn)
	if cert == nil {
		C.free(cData)
		return nil, errors.New("bee2: failed to allocate bake_cert")
	}
	return &BakeCert{cert: cert, data: cData, owned: true}, nil
}

// NewBakeCertFromC wraps a bake_cert already configured on the C side.
// The caller is responsible for the lifetime of the underlying memory.
func NewBakeCertFromC(certPtr unsafe.Pointer) *BakeCert {
	return &BakeCert{cert: (*C.bake_cert)(certPtr), owned: false}
}

// Free releases C memory owned by this BakeCert.
func (c *BakeCert) Free() {
	if !c.owned {
		return
	}
	if c.data != nil {
		C.free(c.data)
		c.data = nil
	}
	if c.cert != nil {
		C.free(unsafe.Pointer(c.cert))
		c.cert = nil
	}
}

// ────────────────────────────────────────────────────────────────────────────
// BakeBSTS
// ────────────────────────────────────────────────────────────────────────────

// BakeBSTS wraps the BSTS authenticated key-establishment protocol state
// (СТБ 34.101.66, algorithm BSTS).
//
// Protocol flow (A initiates, B responds):
//
//	B: stB = NewBakeBSTS(...)   A: stA = NewBakeBSTS(...)
//	B: m1, _ = stB.Step2()           → send m1 →
//	                                  A: m2, _ = stA.Step3(m1)
//	                                  ← send m2 ←
//	B: m3, _ = stB.Step4(m2, valA)   → send m3 →
//	                                  A: stA.Step5(m3, valB)
//	B: key, _ = stB.StepG()   A: key, _ = stA.StepG()
type BakeBSTS struct {
	state   unsafe.Pointer
	l       int
	certLen int
}

// NewBakeBSTS initialises the BSTS state for one party.
// l is the security level in bits (128, 192, or 256).
// privKey must be l/4 bytes.
func NewBakeBSTS(l int, params *BignParams, settings *BakeSettings, privKey []byte, cert *BakeCert) (*BakeBSTS, error) {
	if params == nil || settings == nil || cert == nil {
		return nil, errors.New("bee2: params, settings, and cert must not be nil")
	}
	state := C.malloc(C.size_t(C.bakeBSTS_keep(C.size_t(l))))
	if state == nil {
		return nil, errors.New("bee2: failed to allocate bakeBSTS state")
	}
	var privKeyPtr *C.octet
	if len(privKey) > 0 {
		privKeyPtr = (*C.octet)(unsafe.Pointer(&privKey[0]))
	}
	rc := C.bakeBSTSStart(state, params.params, settings.settings, privKeyPtr, cert.cert)
	if rc != 0 {
		C.free(state)
		return nil, errors.New("bee2: bakeBSTSStart failed")
	}
	return &BakeBSTS{state: state, l: l, certLen: int(cert.cert.len)}, nil
}

// Free releases the underlying C state.
func (b *BakeBSTS) Free() {
	if b.state != nil {
		C.free(b.state)
		b.state = nil
	}
}

// Step2 is called by party B to produce message M1 (l/2 bytes).
func (b *BakeBSTS) Step2() ([]byte, error) {
	out := make([]byte, b.l/2)
	if rc := C.bakeBSTSStep2((*C.octet)(unsafe.Pointer(&out[0])), b.state); rc != 0 {
		return nil, errors.New("bee2: bakeBSTSStep2 failed")
	}
	return out, nil
}

// Step3 is called by party A: processes M1 and produces M2.
// Output size: 3*l/4 + certLen + 8 bytes.
func (b *BakeBSTS) Step3(in []byte) ([]byte, error) {
	out := make([]byte, 3*b.l/4+b.certLen+8)
	var inPtr *C.octet
	if len(in) > 0 {
		inPtr = (*C.octet)(unsafe.Pointer(&in[0]))
	}
	if rc := C.bakeBSTSStep3((*C.octet)(unsafe.Pointer(&out[0])), inPtr, b.state); rc != 0 {
		return nil, errors.New("bee2: bakeBSTSStep3 failed")
	}
	return out, nil
}

// Step4 is called by party B: processes M2 and produces M3.
// Output size: l/4 + certLen + 8 bytes.
// vala is a C bake_certval_i pointer used to validate A's certificate in M2.
func (b *BakeBSTS) Step4(in []byte, vala unsafe.Pointer) ([]byte, error) {
	out := make([]byte, b.l/4+b.certLen+8)
	var inPtr *C.octet
	if len(in) > 0 {
		inPtr = (*C.octet)(unsafe.Pointer(&in[0]))
	}
	rc := C.bsts_step4_wrap(
		(*C.octet)(unsafe.Pointer(&out[0])),
		inPtr, C.size_t(len(in)),
		vala, b.state,
	)
	if rc != 0 {
		return nil, errors.New("bee2: bakeBSTSStep4 failed")
	}
	return out, nil
}

// Step5 is called by party A: processes M3 and finalises the handshake.
// valb is a C bake_certval_i pointer used to validate B's certificate in M3.
func (b *BakeBSTS) Step5(in []byte, valb unsafe.Pointer) error {
	var inPtr *C.octet
	if len(in) > 0 {
		inPtr = (*C.octet)(unsafe.Pointer(&in[0]))
	}
	if rc := C.bsts_step5_wrap(inPtr, C.size_t(len(in)), valb, b.state); rc != 0 {
		return errors.New("bee2: bakeBSTSStep5 failed")
	}
	return nil
}

// StepG extracts the 32-byte shared session key after the protocol completes.
// Call after Step4 (party B) or Step5 (party A).
func (b *BakeBSTS) StepG() ([]byte, error) {
	key := make([]byte, 32)
	if rc := C.bakeBSTSStepG((*C.octet)(unsafe.Pointer(&key[0])), b.state); rc != 0 {
		return nil, errors.New("bee2: bakeBSTSStepG failed")
	}
	return key, nil
}

// ────────────────────────────────────────────────────────────────────────────
// BakeBPACE
// ────────────────────────────────────────────────────────────────────────────

// BakeBPACE wraps the BPACE password-authenticated key-establishment protocol
// state (СТБ 34.101.66, algorithm BPACE).
//
// Protocol flow:
//
//	B: m1 = Step2()                 → send M1 →
//	                                  A: m2 = Step3(m1)
//	                                  ← send M2 ←
//	B: m3 = Step4(m2)               → send M3 →
//	                                  A: m4 = Step5(m3)
//	                                  ← send M4 ←
//	B: Step6(m4)
//	A/B: key = StepG()
type BakeBPACE struct {
	state unsafe.Pointer
	l     int
	kca   bool
	kcb   bool
}

// NewBakeBPACE initialises one BPACE party.
// l is the security level in bits (128, 192, or 256).
func NewBakeBPACE(l int, params *BignParams, settings *BakeSettings, password []byte) (*BakeBPACE, error) {
	if params == nil || settings == nil {
		return nil, errors.New("bee2: params and settings must not be nil")
	}
	if l != 128 && l != 192 && l != 256 {
		return nil, errors.New("bee2: unsupported BPACE security level")
	}
	if len(password) == 0 {
		return nil, errors.New("bee2: BPACE password is empty")
	}

	state := C.malloc(C.size_t(C.bakeBPACE_keep(C.size_t(l))))
	if state == nil {
		return nil, errors.New("bee2: failed to allocate bakeBPACE state")
	}
	rc := C.bakeBPACEStart(
		state,
		params.params,
		settings.settings,
		(*C.octet)(unsafe.Pointer(&password[0])),
		C.size_t(len(password)),
	)
	if rc != 0 {
		C.free(state)
		return nil, errors.New("bee2: bakeBPACEStart failed")
	}
	return &BakeBPACE{
		state: state,
		l:     l,
		kca:   settings.settings.kca != 0,
		kcb:   settings.settings.kcb != 0,
	}, nil
}

// Free releases the underlying C state.
func (b *BakeBPACE) Free() {
	if b.state != nil {
		C.free(b.state)
		b.state = nil
	}
}

// Step2 is called by party B to produce M1 (l/8 bytes).
func (b *BakeBPACE) Step2() ([]byte, error) {
	out := make([]byte, b.l/8)
	if rc := C.bakeBPACEStep2((*C.octet)(unsafe.Pointer(&out[0])), b.state); rc != 0 {
		return nil, errors.New("bee2: bakeBPACEStep2 failed")
	}
	return out, nil
}

// Step3 is called by party A: processes M1 and produces M2 (5*l/8 bytes).
func (b *BakeBPACE) Step3(in []byte) ([]byte, error) {
	if len(in) != b.l/8 {
		return nil, errors.New("bee2: BPACE M1 has invalid length")
	}
	out := make([]byte, 5*b.l/8)
	if rc := C.bakeBPACEStep3(
		(*C.octet)(unsafe.Pointer(&out[0])),
		(*C.octet)(unsafe.Pointer(&in[0])),
		b.state,
	); rc != 0 {
		return nil, errors.New("bee2: bakeBPACEStep3 failed")
	}
	return out, nil
}

// Step4 is called by party B: processes M2 and produces M3.
// Output size is l/2 bytes plus 8 bytes when party B confirms the key.
func (b *BakeBPACE) Step4(in []byte) ([]byte, error) {
	if len(in) != 5*b.l/8 {
		return nil, errors.New("bee2: BPACE M2 has invalid length")
	}
	outLen := b.l / 2
	if b.kcb {
		outLen += 8
	}
	out := make([]byte, outLen)
	if rc := C.bakeBPACEStep4(
		(*C.octet)(unsafe.Pointer(&out[0])),
		(*C.octet)(unsafe.Pointer(&in[0])),
		b.state,
	); rc != 0 {
		return nil, errors.New("bee2: bakeBPACEStep4 failed")
	}
	return out, nil
}

// Step5 is called by party A: processes M3 and produces M4 when party A
// confirms the key.
func (b *BakeBPACE) Step5(in []byte) ([]byte, error) {
	inLen := b.l / 2
	if b.kcb {
		inLen += 8
	}
	if len(in) != inLen {
		return nil, errors.New("bee2: BPACE M3 has invalid length")
	}
	outLen := 0
	if b.kca {
		outLen = 8
	}
	out := make([]byte, outLen)
	var outPtr *C.octet
	if len(out) > 0 {
		outPtr = (*C.octet)(unsafe.Pointer(&out[0]))
	}
	if rc := C.bakeBPACEStep5(
		outPtr,
		(*C.octet)(unsafe.Pointer(&in[0])),
		b.state,
	); rc != 0 {
		return nil, errors.New("bee2: bakeBPACEStep5 failed")
	}
	return out, nil
}

// Step6 is called by party B to verify M4 when party A confirms the key.
func (b *BakeBPACE) Step6(in []byte) error {
	if !b.kca {
		if len(in) == 0 {
			return nil
		}
		return errors.New("bee2: BPACE M4 supplied when kca is disabled")
	}
	if len(in) != 8 {
		return errors.New("bee2: BPACE M4 has invalid length")
	}
	if rc := C.bakeBPACEStep6((*C.octet)(unsafe.Pointer(&in[0])), b.state); rc != 0 {
		return errors.New("bee2: bakeBPACEStep6 failed")
	}
	return nil
}

// StepG extracts the 32-byte shared key after the protocol completes.
func (b *BakeBPACE) StepG() ([]byte, error) {
	key := make([]byte, 32)
	if rc := C.bakeBPACEStepG((*C.octet)(unsafe.Pointer(&key[0])), b.state); rc != 0 {
		return nil, errors.New("bee2: bakeBPACEStepG failed")
	}
	return key, nil
}
