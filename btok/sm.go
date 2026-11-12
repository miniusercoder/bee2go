package btok

import "github.com/miniusercoder/bee2go/v3/internal/native"

type Command struct {
	CLA, INS, P1, P2 byte
	Data             []byte
	ResponseLength   int
}
type Response struct {
	SW1, SW2 byte
	Data     []byte
}

// SecureMessaging advances its counter for each protected operation. A failed
// cryptographic operation or malformed incoming packet makes the session unusable;
// invalid outgoing inputs detected before an operation can be corrected and retried.
type SecureMessaging struct{ state *native.SecureMessaging }

func NewSecureMessaging(key []byte) (*SecureMessaging, error) {
	s, e := native.NewSecureMessaging(key)
	if e != nil {
		return nil, e
	}
	return &SecureMessaging{s}, nil
}
func (s *SecureMessaging) Close() error { return s.state.Close() }
func (s *SecureMessaging) WrapCommand(cmd Command) ([]byte, error) {
	return s.state.WrapCommand(native.SMCommand(cmd))
}
func (s *SecureMessaging) UnwrapCommand(wire []byte) (Command, error) {
	cmd, e := s.state.UnwrapCommand(wire)
	return Command(cmd), e
}
func (s *SecureMessaging) WrapResponse(resp Response) ([]byte, error) {
	return s.state.WrapResponse(native.SMResponse(resp))
}
func (s *SecureMessaging) UnwrapResponse(wire []byte) (Response, error) {
	resp, e := s.state.UnwrapResponse(wire)
	return Response(resp), e
}
