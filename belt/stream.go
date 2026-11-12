package belt

import "github.com/miniusercoder/bee2go/v3/internal/native"

// Stream processes data in place. ECB and CBC Update requires whole blocks;
// Final accepts the remaining 16 or more bytes, including a stolen block.
type Stream struct{ n *native.BeltStream }

func newStream(mode int, key, iv []byte, decrypt bool) (*Stream, error) {
	s, e := native.NewBeltStream(mode, key, iv, decrypt)
	if e != nil {
		return nil, e
	}
	return &Stream{s}, nil
}
func NewECB(key []byte, decrypt bool) (*Stream, error)     { return newStream(0, key, nil, decrypt) }
func NewCBC(key, iv []byte, decrypt bool) (*Stream, error) { return newStream(1, key, iv, decrypt) }
func NewCFB(key, iv []byte, decrypt bool) (*Stream, error) { return newStream(2, key, iv, decrypt) }
func NewCTR(key, iv []byte) (*Stream, error)               { return newStream(3, key, iv, false) }
func NewBDE(key, iv []byte, decrypt bool) (*Stream, error) { return newStream(4, key, iv, decrypt) }
func (s *Stream) Update(b []byte) error                    { return s.n.Crypt(b, false) }
func (s *Stream) Final(b []byte) error                     { return s.n.Crypt(b, true) }
func (s *Stream) Refresh(iv []byte) error                  { return s.n.Refresh(iv) }
func (s *Stream) Close() error {
	if s == nil {
		return nil
	}
	return s.n.Close()
}
