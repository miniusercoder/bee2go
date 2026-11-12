package btok

import (
	"bytes"
	"encoding/hex"
	"errors"
	bee2 "github.com/miniusercoder/bee2go/v3"
	"testing"
)

func TestSecureMessagingVector(t *testing.T) {
	key, _ := hex.DecodeString("B194BAC80A08F53B366D008E584A5DE48504FA9D1BB6C7AC252E72C202FDCE0D")
	a, e := NewSecureMessaging(key)
	if e != nil {
		t.Fatal(e)
	}
	defer a.Close()
	b, e := NewSecureMessaging(key)
	if e != nil {
		t.Fatal(e)
	}
	defer b.Close()
	cmd := Command{CLA: 0, INS: 0xa4, P1: 4, P2: 4, Data: []byte("Test"), ResponseLength: 256}
	wire, e := a.WrapCommand(cmd)
	if e != nil {
		t.Fatal(e)
	}
	expected, _ := hex.DecodeString("04A40404148705020C4C0BFB9701008E08AD7BCF00950EEBAF00")
	if !bytes.Equal(wire, expected) {
		t.Fatalf("%X", wire)
	}
	got, e := b.UnwrapCommand(wire)
	if e != nil || got.CLA != cmd.CLA || got.INS != cmd.INS || got.ResponseLength != cmd.ResponseLength || !bytes.Equal(got.Data, cmd.Data) {
		t.Fatal(got, e)
	}
	data, _ := hex.DecodeString("E012C00401FF8010C00402FF8010C00403FF8010")
	resp := Response{SW1: 0x90, Data: data}
	wire, e = b.WrapResponse(resp)
	if e != nil {
		t.Fatal(e)
	}
	expected, _ = hex.DecodeString("8715022A9042A60A85E50FAB446AC80B75F144B67EBD6D8E08A93DE7D49A1E75909000")
	if !bytes.Equal(wire, expected) {
		t.Fatalf("%X", wire)
	}
	r, e := a.UnwrapResponse(wire)
	if e != nil || r.SW1 != 0x90 || !bytes.Equal(r.Data, data) {
		t.Fatal(r, e)
	}
}
func TestSecureMessagingRejectsTampering(t *testing.T) {
	key := make([]byte, 32)
	a, _ := NewSecureMessaging(key)
	b, _ := NewSecureMessaging(key)
	defer a.Close()
	defer b.Close()
	wire, e := a.WrapCommand(Command{INS: 0xa4, Data: []byte("secret")})
	if e != nil {
		t.Fatal(e)
	}
	wire[len(wire)-2] ^= 1
	cmd, e := b.UnwrapCommand(wire)
	if e == nil || cmd.Data != nil {
		t.Fatal("accepted bad MAC")
	}
	if _, e = NewSecureMessaging(make([]byte, 31)); e == nil {
		t.Fatal("bad key")
	}
	if _, e = a.WrapCommand(Command{}); e == nil {
		t.Fatal("wrong order")
	}
}
func TestSecureMessagingLengthsAndOrder(t *testing.T) {
	for _, n := range []int{0, 1, 255, 256, 257} {
		key := make([]byte, 32)
		a, e := NewSecureMessaging(key)
		if e != nil {
			t.Fatal(e)
		}
		b, _ := NewSecureMessaging(key)
		msg := Command{INS: 0xa4, Data: bytes.Repeat([]byte{0x36}, n), ResponseLength: 256}
		wire, e := a.WrapCommand(msg)
		if e != nil {
			t.Fatal(n, e)
		}
		cmd, e := b.UnwrapCommand(wire)
		if e != nil || !bytes.Equal(cmd.Data, msg.Data) {
			t.Fatal(n, e)
		}
		resp := Response{SW1: 0x90, Data: bytes.Repeat([]byte{1}, n)}
		wire, e = b.WrapResponse(resp)
		if e != nil {
			t.Fatal(n, e)
		}
		out, e := a.UnwrapResponse(wire)
		if e != nil || !bytes.Equal(out.Data, resp.Data) {
			t.Fatal(n, e)
		}
		a.Close()
		b.Close()
	}
	a, _ := NewSecureMessaging(make([]byte, 32))
	defer a.Close()
	if _, e := a.WrapResponse(Response{}); e == nil {
		t.Fatal("response before command")
	}
	if _, e := a.WrapCommand(Command{CLA: 4}); e == nil {
		t.Fatal("protected CLA")
	}
	if _, e := a.UnwrapCommand([]byte{0}); e == nil {
		t.Fatal("bad packet")
	}
}
func FuzzSecureMessaging(f *testing.F) {
	f.Add([]byte{0})
	f.Add([]byte{4, 0xa4, 4, 4, 0})
	f.Fuzz(func(t *testing.T, wire []byte) {
		if len(wire) > 4096 {
			return
		}
		s, e := NewSecureMessaging(make([]byte, 32))
		if e != nil {
			t.Fatal(e)
		}
		defer s.Close()
		_, _ = s.UnwrapCommand(wire)
	})
}
func TestSecureMessagingResponseTampering(t *testing.T) {
	key := make([]byte, 32)
	a, _ := NewSecureMessaging(key)
	b, _ := NewSecureMessaging(key)
	defer a.Close()
	defer b.Close()
	cmd, e := a.WrapCommand(Command{})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = b.UnwrapCommand(cmd); e != nil {
		t.Fatal(e)
	}
	wire, e := b.WrapResponse(Response{SW1: 0x90, Data: []byte("secret")})
	if e != nil {
		t.Fatal(e)
	}
	wire[len(wire)-3] ^= 1
	out, e := a.UnwrapResponse(wire)
	if e == nil || out.Data != nil {
		t.Fatal("accepted bad response MAC")
	}
}
func TestSecureMessagingClosed(t *testing.T) {
	s, e := NewSecureMessaging(make([]byte, 32))
	if e != nil {
		t.Fatal(e)
	}
	s.Close()
	if _, e = s.WrapCommand(Command{}); !errors.Is(e, bee2.ErrClosed) {
		t.Fatalf("wrap command: %v", e)
	}
	if _, e = s.UnwrapCommand(nil); !errors.Is(e, bee2.ErrClosed) {
		t.Fatalf("unwrap command: %v", e)
	}
	if _, e = s.WrapResponse(Response{}); !errors.Is(e, bee2.ErrClosed) {
		t.Fatalf("wrap response: %v", e)
	}
	if _, e = s.UnwrapResponse(nil); !errors.Is(e, bee2.ErrClosed) {
		t.Fatalf("unwrap response: %v", e)
	}
}
func TestSecureMessagingMaximumLengths(t *testing.T) {
	key := make([]byte, 32)
	a, _ := NewSecureMessaging(key)
	b, _ := NewSecureMessaging(key)
	defer a.Close()
	defer b.Close()
	if _, e := a.WrapCommand(Command{Data: make([]byte, 65536)}); e == nil {
		t.Fatal("oversized command")
	}
	if _, e := a.WrapCommand(Command{ResponseLength: 65537}); e == nil {
		t.Fatal("oversized response length")
	}
	if _, e := a.WrapCommand(Command{Data: make([]byte, 65535)}); e == nil {
		t.Fatal("protected command exceeds encoding")
	}
	wire, e := a.WrapCommand(Command{Data: make([]byte, 65000), ResponseLength: 65536})
	if e != nil {
		t.Fatal(e)
	}
	cmd, e := b.UnwrapCommand(wire)
	if e != nil || len(cmd.Data) != 65000 || cmd.ResponseLength != 65536 {
		t.Fatal(e)
	}
	if _, e = b.WrapResponse(Response{Data: make([]byte, 65537)}); e == nil {
		t.Fatal("oversized response")
	}
	if _, e = b.WrapResponse(Response{Data: make([]byte, 65536)}); e == nil {
		t.Fatal("protected response exceeds encoding")
	}
	wire, e = b.WrapResponse(Response{Data: make([]byte, 65000), SW1: 0x90})
	if e != nil {
		t.Fatal(e)
	}
	resp, e := a.UnwrapResponse(wire)
	if e != nil || len(resp.Data) != 65000 {
		t.Fatal(e)
	}
}
func TestSecureMessagingFailureClosesProtocol(t *testing.T) {
	key := make([]byte, 32)
	a, _ := NewSecureMessaging(key)
	b, _ := NewSecureMessaging(key)
	defer a.Close()
	defer b.Close()
	wire, e := a.WrapCommand(Command{Data: []byte("secret")})
	if e != nil {
		t.Fatal(e)
	}
	wire[len(wire)-2] ^= 1
	cmd, e := b.UnwrapCommand(wire)
	if e == nil || cmd.Data != nil {
		t.Fatal("bad command accepted")
	}
	if wire, e := b.WrapResponse(Response{SW1: 0x90, Data: []byte("accepted")}); !errors.Is(e, bee2.ErrState) || wire != nil {
		t.Fatal("response after authentication failure", e)
	}
	if _, e = b.UnwrapCommand(nil); !errors.Is(e, bee2.ErrState) {
		t.Fatal("continued after authentication failure", e)
	}
	if _, e = a.WrapCommand(Command{}); !errors.Is(e, bee2.ErrState) {
		t.Fatal("wrong order", e)
	}
}
func TestSecureMessagingResponseFailureStopsSession(t *testing.T) {
	key := make([]byte, 32)
	a, _ := NewSecureMessaging(key)
	b, _ := NewSecureMessaging(key)
	defer a.Close()
	defer b.Close()
	wire, _ := a.WrapCommand(Command{})
	if _, e := b.UnwrapCommand(wire); e != nil {
		t.Fatal(e)
	}
	wire, e := b.WrapResponse(Response{Data: []byte("secret"), SW1: 0x90})
	if e != nil {
		t.Fatal(e)
	}
	wire[len(wire)-3] ^= 1
	out, e := a.UnwrapResponse(wire)
	if e == nil || out.Data != nil {
		t.Fatal("bad response accepted")
	}
	if _, e = a.WrapCommand(Command{}); !errors.Is(e, bee2.ErrState) {
		t.Fatal("continued after failed response", e)
	}
}
func TestSecureMessagingMalformedIncomingStopsSession(t *testing.T) {
	s, _ := NewSecureMessaging(make([]byte, 32))
	defer s.Close()
	if _, e := s.UnwrapCommand([]byte{0}); e == nil {
		t.Fatal("malformed accepted")
	}
	if _, e := s.UnwrapCommand([]byte{0}); !errors.Is(e, bee2.ErrState) {
		t.Fatal("session accepted operation after protocol error", e)
	}
}
