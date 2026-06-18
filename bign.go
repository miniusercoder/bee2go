package bee2go

/*
#cgo CFLAGS: -I${SRCDIR}/bee2/include
#cgo LDFLAGS: -L${SRCDIR}/bee2/build/src -lbee2_static
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "bee2/core/err.h"
#include "bee2/crypto/belt.h"
#include "bee2/crypto/bign.h"
#include "bee2/crypto/brng.h"

// urandom_gen is a gen_i that reads from /dev/urandom. Declared here as a
// non-static C function so other translation units can reference it via the
// extern declaration below. CGO cannot convert a Go function to a C function
// pointer, so we use this C-side generator for all randomised operations.
void urandom_gen(void* buf, size_t count, void* state) {
	FILE* f = fopen("/dev/urandom", "rb");
	if (f) {
		size_t got = fread(buf, 1, count, f);
		fclose(f);
		// /dev/urandom does not short-read in practice; zero any shortfall so
		// the gen_i contract (all count octets produced) still holds.
		if (got < count)
			memset((octet*)buf + got, 0, count - got);
	}
}

// C wrappers that accept the rng/id arguments as void* so CGO does not need
// to know the function-pointer types at the Go call site.

static err_t _bignSign(
	octet* sig, const bign_params* p,
	const octet* oid, size_t oid_len,
	const octet* hash, const octet* priv)
{
	return bignSign(sig, p, oid, oid_len, hash, priv, urandom_gen, NULL);
}

static err_t _bignSign2(
	octet* sig, const bign_params* p,
	const octet* oid, size_t oid_len,
	const octet* hash, const octet* priv,
	const void* t, size_t t_len)
{
	return bignSign2(sig, p, oid, oid_len, hash, priv, t, t_len);
}

static err_t _bignKeyWrap(
	octet* token, const bign_params* p,
	const octet* key, size_t key_len,
	const octet* header, const octet* pub)
{
	return bignKeyWrap(token, p, key, key_len, header, pub, urandom_gen, NULL);
}

static err_t _bignIdSign(
	octet* sig, const bign_params* p,
	const octet* oid, size_t oid_len,
	const octet* id_hash, const octet* hash,
	const octet* id_priv)
{
	return bignIdSign(sig, p, oid, oid_len, id_hash, hash, id_priv, urandom_gen, NULL);
}

static err_t _bignIdSign2(
	octet* sig, const bign_params* p,
	const octet* oid, size_t oid_len,
	const octet* id_hash, const octet* hash,
	const octet* id_priv, const void* t, size_t t_len)
{
	return bignIdSign2(sig, p, oid, oid_len, id_hash, hash, id_priv, t, t_len);
}

static err_t _bignKeypairGen(
	octet* priv, octet* pub, const bign_params* p)
{
	return bignKeypairGen(priv, pub, p, urandom_gen, NULL);
}

typedef struct
{
	const octet* X;
	size_t count;
	size_t offset;
	unsigned char state_ex[];
} bee2go_brng_ctrx_st;

static size_t bee2go_brng_ctrx_keep(void)
{
	return sizeof(bee2go_brng_ctrx_st) + brngCTR_keep();
}

static void bee2go_brng_ctrx_start(const octet key[32], const octet iv[32],
	const void* X, size_t count, void* state)
{
	bee2go_brng_ctrx_st* s = (bee2go_brng_ctrx_st*)state;
	brngCTRStart(s->state_ex, key, iv);
	s->X = (const octet*)X;
	s->count = count;
	s->offset = 0;
}

static void bee2go_brng_ctrx_step_r(void* buf, size_t count, void* state)
{
	bee2go_brng_ctrx_st* s = (bee2go_brng_ctrx_st*)state;
	octet* dst = (octet*)buf;
	size_t left = count;
	while (left)
	{
		size_t chunk = s->count - s->offset;
		if (chunk > left)
			chunk = left;
		memcpy(dst, s->X + s->offset, chunk);
		dst += chunk;
		left -= chunk;
		s->offset += chunk;
		if (s->offset == s->count)
			s->offset = 0;
	}
	brngCTRStepR(buf, count, s->state_ex);
}

static err_t _bignKeypairGenBeltH(octet* priv, octet* pub, const bign_params* p)
{
	err_t rc;
	void* state = malloc(bee2go_brng_ctrx_keep());
	if (!state)
		return ERR_OUTOFMEMORY;
	bee2go_brng_ctrx_start(beltH() + 128, beltH() + 128 + 64, beltH(), 8 * 32, state);
	rc = bignKeypairGen(priv, pub, p, bee2go_brng_ctrx_step_r, state);
	free(state);
	return rc;
}

static err_t _bignDHBeltG(octet* key, const bign_params* p,
	const octet* priv, size_t key_len)
{
	octet pub[128];
	size_t no = p->l / 4;
	memset(pub, 0, sizeof(pub));
	memcpy(pub + no, p->yG, no);
	return bignDH(key, p, priv, pub, key_len);
}
*/
import "C"
import (
	"errors"
	"unsafe"
)

const (
	// OIDBeltHash is the dotted-decimal OID for the belt-hash algorithm,
	// used as hash algorithm identifier in bign sign/verify calls.
	OIDBeltHash = "1.2.112.0.2.0.34.101.31.81"

	bignCurve256v1 = "1.2.112.0.2.0.34.101.45.3.1"
	bignCurve384v1 = "1.2.112.0.2.0.34.101.45.3.2"
	bignCurve512v1 = "1.2.112.0.2.0.34.101.45.3.3"
)

// ────────────────────────────────────────────────────────────────────────────
// BignParams
// ────────────────────────────────────────────────────────────────────────────

// BignParams wraps bign long-term parameters (bign_params, STB 34.101.45 §5.3).
type BignParams struct {
	params *C.bign_params
}

// NewBignParamsStd loads a named standard parameter set.
//
//   - "1.2.112.0.2.0.34.101.45.3.1"  bign-curve256v1  l=128, priv 32 B, pub 64 B
//   - "1.2.112.0.2.0.34.101.45.3.2"  bign-curve384v1  l=192, priv 48 B, pub 96 B
//   - "1.2.112.0.2.0.34.101.45.3.3"  bign-curve512v1  l=256, priv 64 B, pub 128 B
func NewBignParamsStd(oid string) (*BignParams, error) {
	p := (*C.bign_params)(C.malloc(C.size_t(C.sizeof_bign_params)))
	if p == nil {
		return nil, errors.New("bee2: malloc bign_params")
	}
	cs := C.CString(oid)
	defer C.free(unsafe.Pointer(cs))
	if rc := C.bignParamsStd(p, cs); rc != 0 {
		C.free(unsafe.Pointer(p))
		return nil, errors.New("bee2: bignParamsStd: unknown OID")
	}
	return &BignParams{params: p}, nil
}

// NewBignParams256v1 loads bign-curve256v1 (l=128).
func NewBignParams256v1() (*BignParams, error) { return NewBignParamsStd(bignCurve256v1) }

// NewBignParams384v1 loads bign-curve384v1 (l=192).
func NewBignParams384v1() (*BignParams, error) { return NewBignParamsStd(bignCurve384v1) }

// NewBignParams512v1 loads bign-curve512v1 (l=256).
func NewBignParams512v1() (*BignParams, error) { return NewBignParamsStd(bignCurve512v1) }

// Free releases the underlying C memory.
func (p *BignParams) Free() {
	if p.params != nil {
		C.free(unsafe.Pointer(p.params))
		p.params = nil
	}
}

// L returns the security level in bits (128, 192, or 256).
func (p *BignParams) L() int { return int(p.params.l) }

// PrivKeyLen returns the private-key size in bytes (l/4).
func (p *BignParams) PrivKeyLen() int { return int(p.params.l) / 4 }

// PubKeyLen returns the public-key size in bytes (l/2).
func (p *BignParams) PubKeyLen() int { return int(p.params.l) / 2 }

// SigLen returns the signature size in bytes (3*l/8).
func (p *BignParams) SigLen() int { return 3 * int(p.params.l) / 8 }

// ────────────────────────────────────────────────────────────────────────────
// OID helper
// ────────────────────────────────────────────────────────────────────────────

// BignOidToDER converts a dotted-decimal OID string to its DER encoding.
func BignOidToDER(oid string) ([]byte, error) {
	cs := C.CString(oid)
	defer C.free(unsafe.Pointer(cs))

	var derLen C.size_t
	if rc := C.bignOidToDER(nil, &derLen, cs); rc != 0 {
		return nil, errors.New("bee2: bignOidToDER: bad OID")
	}
	der := make([]byte, int(derLen))
	if rc := C.bignOidToDER((*C.octet)(unsafe.Pointer(&der[0])), &derLen, cs); rc != 0 {
		return nil, errors.New("bee2: bignOidToDER failed")
	}
	return der[:int(derLen)], nil
}

// BeltHashOID returns the DER-encoded OID for belt-hash, ready for Sign/Verify.
func BeltHashOID() ([]byte, error) { return BignOidToDER(OIDBeltHash) }

// ────────────────────────────────────────────────────────────────────────────
// Key generation and DH
// ────────────────────────────────────────────────────────────────────────────

// BignKeypairGen generates a random bign keypair using /dev/urandom.
// Returns (privKey [l/4]byte, pubKey [l/2]byte).
func BignKeypairGen(params *BignParams) (privKey, pubKey []byte, err error) {
	if params == nil {
		return nil, nil, errors.New("bee2: params is nil")
	}
	privKey = make([]byte, params.PrivKeyLen())
	pubKey = make([]byte, params.PubKeyLen())
	rc := C._bignKeypairGen(
		(*C.octet)(unsafe.Pointer(&privKey[0])),
		(*C.octet)(unsafe.Pointer(&pubKey[0])),
		params.params,
	)
	if rc != 0 {
		return nil, nil, errors.New("bee2: bignKeypairGen failed")
	}
	return privKey, pubKey, nil
}

func bignKeypairGenBeltH(params *BignParams) (privKey, pubKey []byte, err error) {
	if params == nil {
		return nil, nil, errors.New("bee2: params is nil")
	}
	privKey = make([]byte, params.PrivKeyLen())
	pubKey = make([]byte, params.PubKeyLen())
	rc := C._bignKeypairGenBeltH(
		(*C.octet)(unsafe.Pointer(&privKey[0])),
		(*C.octet)(unsafe.Pointer(&pubKey[0])),
		params.params,
	)
	if rc != 0 {
		return nil, nil, errors.New("bee2: bignKeypairGen KAT failed")
	}
	return privKey, pubKey, nil
}

// BignPubkeyVal validates a bign public key against params.
func BignPubkeyVal(params *BignParams, pubKey []byte) error {
	if params == nil {
		return errors.New("bee2: params is nil")
	}
	if len(pubKey) < params.PubKeyLen() {
		return errors.New("bee2: pubKey too short")
	}
	if rc := C.bignPubkeyVal(params.params, (*C.octet)(unsafe.Pointer(&pubKey[0]))); rc != 0 {
		return errors.New("bee2: bignPubkeyVal failed")
	}
	return nil
}

// BignPubkeyCalc derives the public key from privKey.
func BignPubkeyCalc(params *BignParams, privKey []byte) ([]byte, error) {
	if params == nil {
		return nil, errors.New("bee2: params is nil")
	}
	if len(privKey) < params.PrivKeyLen() {
		return nil, errors.New("bee2: privKey too short")
	}
	pubKey := make([]byte, params.PubKeyLen())
	rc := C.bignPubkeyCalc(
		(*C.octet)(unsafe.Pointer(&pubKey[0])),
		params.params,
		(*C.octet)(unsafe.Pointer(&privKey[0])),
	)
	if rc != 0 {
		return nil, errors.New("bee2: bignPubkeyCalc failed")
	}
	return pubKey, nil
}

// BignDH computes the Diffie-Hellman shared secret privKey*peerPubKey.
// keyLen is the number of desired output bytes (≤ l/2).
func BignDH(params *BignParams, privKey, peerPubKey []byte, keyLen int) ([]byte, error) {
	if params == nil {
		return nil, errors.New("bee2: params is nil")
	}
	if len(privKey) < params.PrivKeyLen() {
		return nil, errors.New("bee2: privKey too short")
	}
	if len(peerPubKey) < params.PubKeyLen() {
		return nil, errors.New("bee2: peerPubKey too short")
	}
	sharedKey := make([]byte, keyLen)
	rc := C.bignDH(
		(*C.octet)(unsafe.Pointer(&sharedKey[0])),
		params.params,
		(*C.octet)(unsafe.Pointer(&privKey[0])),
		(*C.octet)(unsafe.Pointer(&peerPubKey[0])),
		C.size_t(keyLen),
	)
	if rc != 0 {
		return nil, errors.New("bee2: bignDH failed")
	}
	return sharedKey, nil
}

func bignDHBeltG(params *BignParams, privKey []byte, keyLen int) ([]byte, error) {
	if params == nil {
		return nil, errors.New("bee2: params is nil")
	}
	if len(privKey) < params.PrivKeyLen() {
		return nil, errors.New("bee2: privKey too short")
	}
	if keyLen <= 0 || keyLen > params.PubKeyLen() {
		return nil, errors.New("bee2: invalid DH key length")
	}
	sharedKey := make([]byte, keyLen)
	rc := C._bignDHBeltG(
		(*C.octet)(unsafe.Pointer(&sharedKey[0])),
		params.params,
		(*C.octet)(unsafe.Pointer(&privKey[0])),
		C.size_t(keyLen),
	)
	if rc != 0 {
		return nil, errors.New("bee2: bignDH generator KAT failed")
	}
	return sharedKey, nil
}

// ────────────────────────────────────────────────────────────────────────────
// Digital signature (STB 34.101.45 §7.1)
// ────────────────────────────────────────────────────────────────────────────

// BignSign produces a randomised signature over hash using privKey.
// oidDER is the DER-encoded hash algorithm OID (use BeltHashOID()).
// hash must be PrivKeyLen() bytes; returns a SigLen()-byte signature.
func BignSign(params *BignParams, oidDER, hash, privKey []byte) ([]byte, error) {
	if err := checkSignArgs(params, oidDER, hash, privKey); err != nil {
		return nil, err
	}
	sig := make([]byte, params.SigLen())
	rc := C._bignSign(
		(*C.octet)(unsafe.Pointer(&sig[0])),
		params.params,
		(*C.octet)(unsafe.Pointer(&oidDER[0])),
		C.size_t(len(oidDER)),
		(*C.octet)(unsafe.Pointer(&hash[0])),
		(*C.octet)(unsafe.Pointer(&privKey[0])),
	)
	if rc != 0 {
		return nil, errors.New("bee2: bignSign failed")
	}
	return sig, nil
}

// BignSign2 produces a deterministic signature.
// t is optional additional entropy; pass nil for pure RFC-6979-style mode.
func BignSign2(params *BignParams, oidDER, hash, privKey, t []byte) ([]byte, error) {
	if err := checkSignArgs(params, oidDER, hash, privKey); err != nil {
		return nil, err
	}
	sig := make([]byte, params.SigLen())
	var tPtr unsafe.Pointer
	if len(t) > 0 {
		tPtr = unsafe.Pointer(&t[0])
	}
	rc := C._bignSign2(
		(*C.octet)(unsafe.Pointer(&sig[0])),
		params.params,
		(*C.octet)(unsafe.Pointer(&oidDER[0])),
		C.size_t(len(oidDER)),
		(*C.octet)(unsafe.Pointer(&hash[0])),
		(*C.octet)(unsafe.Pointer(&privKey[0])),
		tPtr,
		C.size_t(len(t)),
	)
	if rc != 0 {
		return nil, errors.New("bee2: bignSign2 failed")
	}
	return sig, nil
}

// BignVerify verifies sig over hash using pubKey.
// Returns nil on success, error on invalid signature.
func BignVerify(params *BignParams, oidDER, hash, sig, pubKey []byte) error {
	if params == nil {
		return errors.New("bee2: params is nil")
	}
	if len(oidDER) == 0 || len(hash) < params.PrivKeyLen() ||
		len(sig) < params.SigLen() || len(pubKey) < params.PubKeyLen() {
		return errors.New("bee2: BignVerify: argument too short")
	}
	rc := C.bignVerify(
		params.params,
		(*C.octet)(unsafe.Pointer(&oidDER[0])),
		C.size_t(len(oidDER)),
		(*C.octet)(unsafe.Pointer(&hash[0])),
		(*C.octet)(unsafe.Pointer(&sig[0])),
		(*C.octet)(unsafe.Pointer(&pubKey[0])),
	)
	if rc != 0 {
		return errors.New("bee2: bignVerify: invalid signature")
	}
	return nil
}

// ────────────────────────────────────────────────────────────────────────────
// Key transport (STB 34.101.45 §7.2)
// ────────────────────────────────────────────────────────────────────────────

// BignKeyWrap encrypts key under recipientPubKey.
// key must be ≥ 16 bytes; header is optional (must be 16 bytes or nil).
// Returns a token of len(key) + PrivKeyLen() + 16 bytes.
func BignKeyWrap(params *BignParams, key, header, recipientPubKey []byte) ([]byte, error) {
	if params == nil {
		return nil, errors.New("bee2: params is nil")
	}
	if len(key) < 16 {
		return nil, errors.New("bee2: key must be ≥ 16 bytes")
	}
	if len(recipientPubKey) < params.PubKeyLen() {
		return nil, errors.New("bee2: recipientPubKey too short")
	}
	token := make([]byte, len(key)+params.PrivKeyLen()+16)
	var hdrPtr *C.octet
	if len(header) >= 16 {
		hdrPtr = (*C.octet)(unsafe.Pointer(&header[0]))
	}
	rc := C._bignKeyWrap(
		(*C.octet)(unsafe.Pointer(&token[0])),
		params.params,
		(*C.octet)(unsafe.Pointer(&key[0])),
		C.size_t(len(key)),
		hdrPtr,
		(*C.octet)(unsafe.Pointer(&recipientPubKey[0])),
	)
	if rc != 0 {
		return nil, errors.New("bee2: bignKeyWrap failed")
	}
	return token, nil
}

// BignKeyUnwrap decrypts token using privKey.
// header must match the value used in BignKeyWrap (nil means all-zero header).
func BignKeyUnwrap(params *BignParams, token, header, privKey []byte) ([]byte, error) {
	if params == nil {
		return nil, errors.New("bee2: params is nil")
	}
	minLen := params.PrivKeyLen() + 16 + 16
	if len(token) < minLen {
		return nil, errors.New("bee2: token too short")
	}
	if len(privKey) < params.PrivKeyLen() {
		return nil, errors.New("bee2: privKey too short")
	}
	key := make([]byte, len(token)-params.PrivKeyLen()-16)
	var hdrPtr *C.octet
	if len(header) >= 16 {
		hdrPtr = (*C.octet)(unsafe.Pointer(&header[0]))
	}
	rc := C.bignKeyUnwrap(
		(*C.octet)(unsafe.Pointer(&key[0])),
		params.params,
		(*C.octet)(unsafe.Pointer(&token[0])),
		C.size_t(len(token)),
		hdrPtr,
		(*C.octet)(unsafe.Pointer(&privKey[0])),
	)
	if rc != 0 {
		return nil, errors.New("bee2: bignKeyUnwrap failed")
	}
	return key, nil
}

// ────────────────────────────────────────────────────────────────────────────
// Identity-based signature (STB 34.101.45 annex B)
// ────────────────────────────────────────────────────────────────────────────

// BignIdExtract derives an identity-based keypair from the master public key
// and a master signature (idSig) over the identity hash (idHash).
func BignIdExtract(params *BignParams, oidDER, idHash, idSig, masterPubKey []byte) (idPrivKey, idPubKey []byte, err error) {
	if params == nil {
		return nil, nil, errors.New("bee2: params is nil")
	}
	if len(oidDER) == 0 || len(idHash) < params.PrivKeyLen() ||
		len(idSig) < params.SigLen() || len(masterPubKey) < params.PubKeyLen() {
		return nil, nil, errors.New("bee2: BignIdExtract: argument too short")
	}
	idPrivKey = make([]byte, params.PrivKeyLen())
	idPubKey = make([]byte, params.PubKeyLen())
	rc := C.bignIdExtract(
		(*C.octet)(unsafe.Pointer(&idPrivKey[0])),
		(*C.octet)(unsafe.Pointer(&idPubKey[0])),
		params.params,
		(*C.octet)(unsafe.Pointer(&oidDER[0])),
		C.size_t(len(oidDER)),
		(*C.octet)(unsafe.Pointer(&idHash[0])),
		(*C.octet)(unsafe.Pointer(&idSig[0])),
		(*C.octet)(unsafe.Pointer(&masterPubKey[0])),
	)
	if rc != 0 {
		return nil, nil, errors.New("bee2: bignIdExtract failed")
	}
	return idPrivKey, idPubKey, nil
}

// BignIdSign produces a randomised identity-based signature over hash.
func BignIdSign(params *BignParams, oidDER, idHash, hash, idPrivKey []byte) ([]byte, error) {
	if err := checkIdSignArgs(params, oidDER, idHash, hash, idPrivKey); err != nil {
		return nil, err
	}
	sig := make([]byte, params.SigLen())
	rc := C._bignIdSign(
		(*C.octet)(unsafe.Pointer(&sig[0])),
		params.params,
		(*C.octet)(unsafe.Pointer(&oidDER[0])),
		C.size_t(len(oidDER)),
		(*C.octet)(unsafe.Pointer(&idHash[0])),
		(*C.octet)(unsafe.Pointer(&hash[0])),
		(*C.octet)(unsafe.Pointer(&idPrivKey[0])),
	)
	if rc != 0 {
		return nil, errors.New("bee2: bignIdSign failed")
	}
	return sig, nil
}

// BignIdSign2 produces a deterministic identity-based signature.
// t is optional additional entropy; pass nil for pure deterministic mode.
func BignIdSign2(params *BignParams, oidDER, idHash, hash, idPrivKey, t []byte) ([]byte, error) {
	if err := checkIdSignArgs(params, oidDER, idHash, hash, idPrivKey); err != nil {
		return nil, err
	}
	sig := make([]byte, params.SigLen())
	var tPtr unsafe.Pointer
	if len(t) > 0 {
		tPtr = unsafe.Pointer(&t[0])
	}
	rc := C._bignIdSign2(
		(*C.octet)(unsafe.Pointer(&sig[0])),
		params.params,
		(*C.octet)(unsafe.Pointer(&oidDER[0])),
		C.size_t(len(oidDER)),
		(*C.octet)(unsafe.Pointer(&idHash[0])),
		(*C.octet)(unsafe.Pointer(&hash[0])),
		(*C.octet)(unsafe.Pointer(&idPrivKey[0])),
		tPtr,
		C.size_t(len(t)),
	)
	if rc != 0 {
		return nil, errors.New("bee2: bignIdSign2 failed")
	}
	return sig, nil
}

// BignIdVerify verifies an identity-based signature.
func BignIdVerify(params *BignParams, oidDER, idHash, hash, idSig, idPubKey, masterPubKey []byte) error {
	if params == nil {
		return errors.New("bee2: params is nil")
	}
	if len(oidDER) == 0 || len(idHash) < params.PrivKeyLen() ||
		len(hash) < params.PrivKeyLen() || len(idSig) < params.SigLen() ||
		len(idPubKey) < params.PubKeyLen() || len(masterPubKey) < params.PubKeyLen() {
		return errors.New("bee2: BignIdVerify: argument too short")
	}
	rc := C.bignIdVerify(
		params.params,
		(*C.octet)(unsafe.Pointer(&oidDER[0])),
		C.size_t(len(oidDER)),
		(*C.octet)(unsafe.Pointer(&idHash[0])),
		(*C.octet)(unsafe.Pointer(&hash[0])),
		(*C.octet)(unsafe.Pointer(&idSig[0])),
		(*C.octet)(unsafe.Pointer(&idPubKey[0])),
		(*C.octet)(unsafe.Pointer(&masterPubKey[0])),
	)
	if rc != 0 {
		return errors.New("bee2: bignIdVerify: invalid signature")
	}
	return nil
}

// ────────────────────────────────────────────────────────────────────────────
// Internal validation helpers
// ────────────────────────────────────────────────────────────────────────────

func checkSignArgs(p *BignParams, oid, hash, priv []byte) error {
	if p == nil {
		return errors.New("bee2: params is nil")
	}
	if len(oid) == 0 {
		return errors.New("bee2: oidDER is empty")
	}
	if len(hash) < p.PrivKeyLen() {
		return errors.New("bee2: hash too short")
	}
	if len(priv) < p.PrivKeyLen() {
		return errors.New("bee2: privKey too short")
	}
	return nil
}

func checkIdSignArgs(p *BignParams, oid, idHash, hash, idPriv []byte) error {
	if p == nil {
		return errors.New("bee2: params is nil")
	}
	if len(oid) == 0 {
		return errors.New("bee2: oidDER is empty")
	}
	if len(idHash) < p.PrivKeyLen() {
		return errors.New("bee2: idHash too short")
	}
	if len(hash) < p.PrivKeyLen() {
		return errors.New("bee2: hash too short")
	}
	if len(idPriv) < p.PrivKeyLen() {
		return errors.New("bee2: idPrivKey too short")
	}
	return nil
}
