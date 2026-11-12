package bake

// Transport carries complete protocol messages. Stream adapters must provide
// their own framing and timeouts. A failed runner closes its session.
type Transport interface {
	Send([]byte) error
	Receive() ([]byte, error)
}

func (s *BSTS) Run(t Transport, validate CertValidator) (key []byte, err error) {
	defer func() {
		if err != nil {
			s.Close()
		}
	}()
	var in, out []byte
	if s.role == RoleB {
		out, err = s.Step2()
		if err != nil {
			return
		}
		if err = t.Send(out); err != nil {
			return
		}
		in, err = t.Receive()
		if err != nil {
			return
		}
		out, err = s.Step4(in, validate)
		if err != nil {
			return
		}
		if err = t.Send(out); err != nil {
			return
		}
	} else {
		in, err = t.Receive()
		if err != nil {
			return
		}
		out, err = s.Step3(in)
		if err != nil {
			return
		}
		if err = t.Send(out); err != nil {
			return
		}
		in, err = t.Receive()
		if err != nil {
			return
		}
		if err = s.Step5(in, validate); err != nil {
			return
		}
	}
	return s.Key()
}
func (s *BMQV) Run(t Transport, peer Certificate) (key []byte, err error) {
	defer func() {
		if err != nil {
			s.Close()
		}
	}()
	var in, out []byte
	if s.role == RoleB {
		out, err = s.Step2()
		if err != nil {
			return
		}
		if err = t.Send(out); err != nil {
			return
		}
		in, err = t.Receive()
		if err != nil {
			return
		}
		out, err = s.Step4(in, peer)
		if err != nil {
			return
		}
		if s.confirmB {
			if err = t.Send(out); err != nil {
				return
			}
		}
	} else {
		in, err = t.Receive()
		if err != nil {
			return
		}
		out, err = s.Step3(in, peer)
		if err != nil {
			return
		}
		if err = t.Send(out); err != nil {
			return
		}
		if s.confirmB {
			in, err = t.Receive()
			if err != nil {
				return
			}
			if err = s.Step5(in); err != nil {
				return
			}
		}
	}
	return s.Key()
}
func (s *BPACE) Run(t Transport) (key []byte, err error) {
	defer func() {
		if err != nil {
			s.Close()
		}
	}()
	var in, out []byte
	if s.role == RoleB {
		out, err = s.Step2()
		if err != nil {
			return
		}
		if err = t.Send(out); err != nil {
			return
		}
		in, err = t.Receive()
		if err != nil {
			return
		}
		out, err = s.Step4(in)
		if err != nil {
			return
		}
		if err = t.Send(out); err != nil {
			return
		}
		if s.confirmA {
			in, err = t.Receive()
			if err != nil {
				return
			}
			if err = s.Step6(in); err != nil {
				return
			}
		}
	} else {
		in, err = t.Receive()
		if err != nil {
			return
		}
		out, err = s.Step3(in)
		if err != nil {
			return
		}
		if err = t.Send(out); err != nil {
			return
		}
		in, err = t.Receive()
		if err != nil {
			return
		}
		out, err = s.Step5(in)
		if err != nil {
			return
		}
		if s.confirmA {
			if err = t.Send(out); err != nil {
				return
			}
		}
	}
	return s.Key()
}
