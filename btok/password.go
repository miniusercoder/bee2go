// Package btok implements Bee2 token protocols.
package btok

import (
	bee2 "github.com/miniusercoder/bee2go/v3"
	"github.com/miniusercoder/bee2go/v3/internal/native"
)

type PINState uint8

const (
	PUKTerminated PINState = iota
	PUK1
	PUK2
	PUK3
	PUK4
	PUK5
	PUK6
	PUK7
	PUK8
	PUK9
	PINLocked
	PINLastAttempt
	PINDeactivated
	PINSuspended
	PINTwoAttempts
	PINOperational
)

type AuthState uint8

const (
	AuthNone AuthState = iota
	AuthPIN
	AuthCAN
	AuthPUK
)

type PasswordEvent uint8

const (
	PINSuccess PasswordEvent = iota
	PINFailure
	PINDeactivate
	PINActivate
	CANSuccess
	CANFailure
	PUKSuccess
	PUKFailure
	AuthClose
)

type PasswordState struct {
	PIN  PINState
	Auth AuthState
}

func (s *PasswordState) Transition(event PasswordEvent) (bool, error) {
	if s == nil {
		return false, bee2.ErrInvalidInput
	}
	p, a, ok, e := native.BTOKPasswordTransition(uint8(s.PIN), uint8(s.Auth), uint8(event))
	if e == nil {
		s.PIN = PINState(p)
		s.Auth = AuthState(a)
	}
	return ok, e
}
