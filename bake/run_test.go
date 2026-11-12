package bake

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

type channelTransport struct{ send, recv chan []byte }

func (c channelTransport) Send(b []byte) error {
	select {
	case c.send <- append([]byte(nil), b...):
		return nil
	case <-time.After(3 * time.Second):
		return errors.New("transport timeout")
	}
}
func (c channelTransport) Receive() ([]byte, error) {
	select {
	case b := <-c.recv:
		return b, nil
	case <-time.After(3 * time.Second):
		return nil, errors.New("transport timeout")
	}
}
func TestRunners(t *testing.T) {
	for _, kind := range []string{"BSTS", "BMQV", "BPACE"} {
		t.Run(kind, func(t *testing.T) {
			p, a, b, ca, cb, v := setup(t)
			settings := Settings{ConfirmA: true, ConfirmB: true}
			ab, ba := make(chan []byte, 4), make(chan []byte, 4)
			ta, tb := channelTransport{ab, ba}, channelTransport{ba, ab}
			result := make(chan struct {
				key []byte
				err error
			}, 2)
			run := func(f func() ([]byte, error)) {
				k, e := f()
				result <- struct {
					key []byte
					err error
				}{k, e}
			}
			switch kind {
			case "BSTS":
				A, e := NewBSTS(p, RoleA, settings, a, Certificate{ca, v})
				if e != nil {
					t.Fatal(e)
				}
				defer A.Close()
				B, e := NewBSTS(p, RoleB, settings, b, Certificate{cb, v})
				if e != nil {
					t.Fatal(e)
				}
				defer B.Close()
				go run(func() ([]byte, error) { return A.Run(ta, v) })
				go run(func() ([]byte, error) { return B.Run(tb, v) })
			case "BMQV":
				A, e := NewBMQV(p, RoleA, settings, a, Certificate{ca, v})
				if e != nil {
					t.Fatal(e)
				}
				defer A.Close()
				B, e := NewBMQV(p, RoleB, settings, b, Certificate{cb, v})
				if e != nil {
					t.Fatal(e)
				}
				defer B.Close()
				go run(func() ([]byte, error) { return A.Run(ta, Certificate{cb, v}) })
				go run(func() ([]byte, error) { return B.Run(tb, Certificate{ca, v}) })
			case "BPACE":
				A, e := NewBPACE(p, RoleA, settings, []byte("pwd"))
				if e != nil {
					t.Fatal(e)
				}
				defer A.Close()
				B, e := NewBPACE(p, RoleB, settings, []byte("pwd"))
				if e != nil {
					t.Fatal(e)
				}
				defer B.Close()
				go run(func() ([]byte, error) { return A.Run(ta) })
				go run(func() ([]byte, error) { return B.Run(tb) })
			}
			x, y := <-result, <-result
			if x.err != nil || y.err != nil || !bytes.Equal(x.key, y.key) {
				t.Fatal(x.err, y.err)
			}
		})
	}
}
