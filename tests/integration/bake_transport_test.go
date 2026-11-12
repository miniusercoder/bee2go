package integration

import (
	"bytes"
	"errors"
	"github.com/miniusercoder/bee2go/v3/bake"
	"github.com/miniusercoder/bee2go/v3/bign"
	"io"
	"testing"
)

var transportFailure = errors.New("transport failure")

type failingTransport struct {
	sendErr, recvErr error
	message          []byte
}

func (t failingTransport) Send([]byte) error        { return t.sendErr }
func (t failingTransport) Receive() ([]byte, error) { return t.message, t.recvErr }
func TestBakeRunnerTransportErrors(t *testing.T) {
	p, e := bign.StandardParams(bign.Curve256v1)
	if e != nil {
		t.Fatal(e)
	}
	defer p.Close()
	priv := make([]byte, 32)
	priv[0] = 1
	pub, e := bign.PublicKey(p, priv)
	if e != nil {
		t.Fatal(e)
	}
	priv2 := make([]byte, 32)
	priv2[0] = 2
	pub2, e := bign.PublicKey(p, priv2)
	if e != nil {
		t.Fatal(e)
	}
	settings := bake.Settings{ConfirmA: true, ConfirmB: true}
	for _, kind := range []string{"bmqv", "bsts", "bpace"} {
		for _, tc := range []struct {
			name string
			role bake.Role
			tr   failingTransport
			want error
		}{{"send", bake.RoleB, failingTransport{sendErr: transportFailure}, transportFailure}, {"receive", bake.RoleA, failingTransport{recvErr: transportFailure}, transportFailure}, {"short_A", bake.RoleA, failingTransport{message: []byte{1}}, nil}, {"short_B", bake.RoleB, failingTransport{message: []byte{1}}, nil}} {
			t.Run(kind+"/"+tc.name, func(t *testing.T) {
				var key []byte
				var runErr error
				switch kind {
				case "bmqv":
					s, e := bake.NewBMQV(p, tc.role, settings, priv, bake.Certificate{Data: pub, Validate: validator(pub)})
					if e != nil {
						t.Fatal(e)
					}
					defer s.Close()
					key, runErr = s.Run(tc.tr, bake.Certificate{Data: pub2, Validate: validator(pub2)})
				case "bsts":
					s, e := bake.NewBSTS(p, tc.role, settings, priv, bake.Certificate{Data: pub, Validate: validator(pub)})
					if e != nil {
						t.Fatal(e)
					}
					defer s.Close()
					key, runErr = s.Run(tc.tr, validator(pub2))
				case "bpace":
					s, e := bake.NewBPACE(p, tc.role, settings, []byte("password"))
					if e != nil {
						t.Fatal(e)
					}
					defer s.Close()
					key, runErr = s.Run(tc.tr)
				}
				if runErr == nil || key != nil {
					t.Fatalf("expected error and no key, got %x, %v", key, runErr)
				}
				if tc.want != nil && !errors.Is(runErr, tc.want) {
					t.Fatalf("expected transport error, got %v", runErr)
				}
			})
		}
	}
}
func TestBakeFrameRejectsTruncatedAndOversized(t *testing.T) {
	for _, b := range [][]byte{{0, 0}, {0, 0, 0, 3, 1}, {0, 1, 0, 1}} {
		tr := frameTransport{r: bytes.NewReader(b), w: io.Discard}
		if _, e := tr.Receive(); e == nil {
			t.Fatalf("accepted %x", b)
		}
	}
}
