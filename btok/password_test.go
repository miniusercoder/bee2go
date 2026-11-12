package btok

import "testing"

func TestPasswordTransitions(t *testing.T) {
	s := PasswordState{PIN: PINOperational}
	steps := []struct {
		event PasswordEvent
		pin   PINState
		auth  AuthState
		ok    bool
	}{{PINSuccess, PINOperational, AuthPIN, true}, {PINDeactivate, PINDeactivated, AuthNone, true}, {PINSuccess, PINDeactivated, AuthNone, false}, {PUKSuccess, PINDeactivated, AuthPUK, true}, {PINActivate, PINOperational, AuthPUK, true}, {CANFailure, PINOperational, AuthPUK, true}, {CANSuccess, PINOperational, AuthCAN, true}, {PINFailure, PINTwoAttempts, AuthCAN, true}, {PINFailure, PINSuspended, AuthCAN, true}, {PINFailure, PINSuspended, AuthCAN, false}, {CANSuccess, PINLastAttempt, AuthCAN, true}, {PINFailure, PINLocked, AuthCAN, true}, {AuthClose, PINLocked, AuthNone, true}}
	for _, step := range steps {
		ok, e := s.Transition(step.event)
		if e != nil || ok != step.ok || s.PIN != step.pin || s.Auth != step.auth {
			t.Fatalf("event %v: %+v %v %v", step.event, s, ok, e)
		}
	}
	for i := 9; i >= 0; i-- {
		ok, e := s.Transition(PUKFailure)
		if e != nil || !ok || int(s.PIN) != i {
			t.Fatal(i, s, ok, e)
		}
	}
	if ok, _ := s.Transition(PINSuccess); ok {
		t.Fatal("terminated PIN")
	}
	if ok, e := s.Transition(PUKSuccess); e != nil || !ok || s.PIN != PUKTerminated {
		t.Fatal(s, e)
	}
	if _, e := s.Transition(255); e == nil {
		t.Fatal("invalid event")
	}
}
func TestPasswordTransitionTable(t *testing.T) {
	for p := PUKTerminated; p <= PINOperational; p++ {
		for a := AuthNone; a <= AuthPUK; a++ {
			for ev := PINSuccess; ev <= AuthClose; ev++ {
				s := PasswordState{p, a}
				want := s
				ok := true
				switch ev {
				case PINSuccess:
					if p != PINLastAttempt && p != PINTwoAttempts && p != PINOperational {
						ok = false
					} else {
						want.PIN = PINOperational
						want.Auth = AuthPIN
					}
				case PINFailure:
					if p != PINLastAttempt && p != PINTwoAttempts && p != PINOperational {
						ok = false
					} else {
						want.PIN--
						if a == AuthPIN {
							want.Auth = AuthNone
						}
					}
				case PINDeactivate:
					if a != AuthPIN && a != AuthPUK {
						ok = false
					} else {
						want.PIN = PINDeactivated
						if a == AuthPIN {
							want.Auth = AuthNone
						}
					}
				case PINActivate:
					if p != PINDeactivated || a != AuthPUK {
						ok = false
					} else {
						want.PIN = PINOperational
					}
				case CANSuccess:
					if p == PINSuspended {
						want.PIN = PINLastAttempt
					}
					want.Auth = AuthCAN
				case CANFailure:
					if a == AuthCAN {
						want.Auth = AuthNone
					}
				case PUKSuccess:
					if p >= PUK1 && p <= PINLocked {
						want.PIN = PINOperational
					}
					want.Auth = AuthPUK
				case PUKFailure:
					if p >= PUK1 && p <= PINLocked {
						want.PIN--
					}
					if a == AuthPUK {
						want.Auth = AuthNone
					}
				case AuthClose:
					if a == AuthNone {
						ok = false
					} else {
						want.Auth = AuthNone
					}
				}
				actual, e := s.Transition(ev)
				if e != nil || actual != ok || s != want {
					t.Fatalf("pin=%d auth=%d event=%d got=%+v %v %v want=%+v %v", p, a, ev, s, actual, e, want, ok)
				}
			}
		}
	}
}
