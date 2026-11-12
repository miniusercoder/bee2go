package native

/*
#include "bridge.h"
#include <bee2/crypto/btok.h>
static apdu_cmd_t* bee2go_sm_cmd(size_t n) {return (apdu_cmd_t*)calloc(1,sizeof(apdu_cmd_t)+n);}
static apdu_resp_t* bee2go_sm_resp(size_t n) {return (apdu_resp_t*)calloc(1,sizeof(apdu_resp_t)+n);}
static octet* bee2go_sm_cmd_data(apdu_cmd_t* p){return p->cdf;}
static octet* bee2go_sm_resp_data(apdu_resp_t* p){return p->rdf;}
*/
import "C"
import (
	bee2 "github.com/miniusercoder/bee2go/v3"
	"unsafe"
)

type SMCommand struct {
	CLA, INS, P1, P2 byte
	Data             []byte
	ResponseLength   int
}
type SMResponse struct {
	SW1, SW2 byte
	Data     []byte
}
type SecureMessaging struct {
	s       *state
	counter [16]byte
	failed  bool
}

func NewSecureMessaging(key []byte) (*SecureMessaging, error) {
	if len(key) != 32 {
		return nil, invalid("btok SM key")
	}
	s, e := newState(uintptr(C.btokSM_keep()))
	if e != nil {
		return nil, e
	}
	C.btokSMStart(s.ptr, octets(key))
	return &SecureMessaging{s: s}, nil
}
func (s *SecureMessaging) Close() error {
	if s == nil {
		return nil
	}
	return s.s.Close()
}
func (s *SecureMessaging) check() error {
	if s == nil {
		return bee2.ErrClosed
	}
	if e := s.s.check(); e != nil {
		return e
	}
	if s.failed {
		return bee2.ErrState
	}
	return nil
}
func (s *SecureMessaging) checkPhase(command bool) error {
	if e := s.check(); e != nil {
		return e
	}
	if (s.counter[0]&1 == 0) != command {
		return bee2.ErrState
	}
	return nil
}
func (s *SecureMessaging) advance(command bool) error {
	if e := s.check(); e != nil {
		return e
	}
	if (s.counter[0]&1 == 0) != command {
		return bee2.ErrState
	}
	full := true
	for _, b := range s.counter {
		if b != 255 {
			full = false
			break
		}
	}
	if full {
		return bee2.ErrState
	}
	for i := range s.counter {
		s.counter[i]++
		if s.counter[i] != 0 {
			break
		}
	}
	C.btokSMCtrInc(s.s.ptr)
	return nil
}
func (s *SecureMessaging) WrapCommand(cmd SMCommand) ([]byte, error) {
	if e := s.checkPhase(true); e != nil {
		return nil, e
	}
	if len(cmd.Data) > 65535 || cmd.ResponseLength < 0 || cmd.ResponseLength > 65536 || cmd.CLA&4 != 0 {
		return nil, invalid("btok SM command")
	}
	p := C.bee2go_sm_cmd(C.size_t(len(cmd.Data)))
	if p == nil {
		return nil, invalid("btok SM allocation")
	}
	defer func() {
		C.memWipe(unsafe.Pointer(p), C.size_t(C.sizeof_apdu_cmd_t+len(cmd.Data)))
		C.free(unsafe.Pointer(p))
	}()
	p.cla = C.octet(cmd.CLA)
	p.ins = C.octet(cmd.INS)
	p.p1 = C.octet(cmd.P1)
	p.p2 = C.octet(cmd.P2)
	p.cdf_len = C.size_t(len(cmd.Data))
	p.rdf_len = C.size_t(cmd.ResponseLength)
	if len(cmd.Data) > 0 {
		C.memcpy(unsafe.Pointer(C.bee2go_sm_cmd_data(p)), pointer(cmd.Data), C.size_t(len(cmd.Data)))
	}
	var n C.size_t
	if e := codeErr("btok SM command size", C.btokSMCmdWrap(nil, &n, p, s.s.ptr)); e != nil {
		return nil, e
	}
	if n == 0 || n > 65543 {
		return nil, invalid("btok SM size")
	}
	if e := s.advance(true); e != nil {
		return nil, e
	}
	out := make([]byte, int(n))
	expected := n
	if e := codeErr("btok SM command wrap", C.btokSMCmdWrap(octets(out), &n, p, s.s.ptr)); e != nil {
		s.failed = true
		Wipe(out)
		return nil, e
	}
	if n != expected {
		s.failed = true
		Wipe(out)
		return nil, invalid("btok SM size")
	}
	return out, nil
}
func (s *SecureMessaging) UnwrapCommand(wire []byte) (SMCommand, error) {
	var out SMCommand
	if e := s.checkPhase(true); e != nil {
		return out, e
	}
	if len(wire) == 0 || len(wire) > 131072 {
		s.failed = true
		return out, invalid("btok SM command")
	}
	var n C.size_t
	if e := codeErr("btok SM command size", C.btokSMCmdUnwrap(nil, &n, octets(wire), C.size_t(len(wire)), s.s.ptr)); e != nil {
		s.failed = true
		return out, e
	}
	if n < C.size_t(C.sizeof_apdu_cmd_t) || n > 131072 {
		s.failed = true
		return out, invalid("btok SM size")
	}
	p := (*C.apdu_cmd_t)(C.calloc(1, n))
	if p == nil {
		return out, invalid("btok SM allocation")
	}
	allocated := n
	defer func() { C.memWipe(unsafe.Pointer(p), allocated); C.free(unsafe.Pointer(p)) }()
	if e := s.advance(true); e != nil {
		return out, e
	}
	capacity := n
	if e := codeErr("btok SM command unwrap", C.btokSMCmdUnwrap(p, &n, octets(wire), C.size_t(len(wire)), s.s.ptr)); e != nil {
		s.failed = true
		return out, e
	}
	if n > capacity || p.cdf_len > capacity-C.size_t(C.sizeof_apdu_cmd_t) {
		s.failed = true
		return out, invalid("btok SM size")
	}
	out = SMCommand{byte(p.cla), byte(p.ins), byte(p.p1), byte(p.p2), C.GoBytes(unsafe.Pointer(C.bee2go_sm_cmd_data(p)), C.int(p.cdf_len)), int(p.rdf_len)}
	return out, nil
}
func (s *SecureMessaging) WrapResponse(resp SMResponse) ([]byte, error) {
	if e := s.checkPhase(false); e != nil {
		return nil, e
	}
	if len(resp.Data) > 65536 {
		return nil, invalid("btok SM response")
	}
	p := C.bee2go_sm_resp(C.size_t(len(resp.Data)))
	if p == nil {
		return nil, invalid("btok SM allocation")
	}
	defer func() {
		C.memWipe(unsafe.Pointer(p), C.size_t(C.sizeof_apdu_resp_t+len(resp.Data)))
		C.free(unsafe.Pointer(p))
	}()
	p.sw1 = C.octet(resp.SW1)
	p.sw2 = C.octet(resp.SW2)
	p.rdf_len = C.size_t(len(resp.Data))
	if len(resp.Data) > 0 {
		C.memcpy(unsafe.Pointer(C.bee2go_sm_resp_data(p)), pointer(resp.Data), C.size_t(len(resp.Data)))
	}
	var n C.size_t
	if e := codeErr("btok SM response size", C.btokSMRespWrap(nil, &n, p, s.s.ptr)); e != nil {
		return nil, e
	}
	if n == 0 || n > 65538 {
		return nil, invalid("btok SM size")
	}
	if e := s.advance(false); e != nil {
		return nil, e
	}
	out := make([]byte, int(n))
	capacity := n
	if e := codeErr("btok SM response wrap", C.btokSMRespWrap(octets(out), &n, p, s.s.ptr)); e != nil {
		s.failed = true
		Wipe(out)
		return nil, e
	}
	if n != capacity {
		s.failed = true
		Wipe(out)
		return nil, invalid("btok SM size")
	}
	return out, nil
}
func (s *SecureMessaging) UnwrapResponse(wire []byte) (SMResponse, error) {
	var out SMResponse
	if e := s.checkPhase(false); e != nil {
		return out, e
	}
	if len(wire) == 0 || len(wire) > 131072 {
		s.failed = true
		return out, invalid("btok SM response")
	}
	var n C.size_t
	if e := codeErr("btok SM response size", C.btokSMRespUnwrap(nil, &n, octets(wire), C.size_t(len(wire)), s.s.ptr)); e != nil {
		s.failed = true
		return out, e
	}
	if n < C.size_t(C.sizeof_apdu_resp_t) || n > 131072 {
		s.failed = true
		return out, invalid("btok SM size")
	}
	p := (*C.apdu_resp_t)(C.calloc(1, n))
	if p == nil {
		return out, invalid("btok SM allocation")
	}
	allocated := n
	defer func() { C.memWipe(unsafe.Pointer(p), allocated); C.free(unsafe.Pointer(p)) }()
	if e := s.advance(false); e != nil {
		return out, e
	}
	capacity := n
	if e := codeErr("btok SM response unwrap", C.btokSMRespUnwrap(p, &n, octets(wire), C.size_t(len(wire)), s.s.ptr)); e != nil {
		s.failed = true
		return out, e
	}
	if n > capacity || p.rdf_len > capacity-C.size_t(C.sizeof_apdu_resp_t) {
		s.failed = true
		return out, invalid("btok SM size")
	}
	out = SMResponse{byte(p.sw1), byte(p.sw2), C.GoBytes(unsafe.Pointer(C.bee2go_sm_resp_data(p)), C.int(p.rdf_len))}
	return out, nil
}
