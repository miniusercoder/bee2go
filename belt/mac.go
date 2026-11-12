package belt

import "github.com/miniusercoder/bee2go/v3/internal/native"

// MACState is a streaming MAC. Close wipes the state and its reset snapshot.
type MACState struct{ n *native.BeltMACState }

func NewMAC(key []byte) (*MACState, error) {
	m, e := native.NewBeltMAC(false, key)
	if e != nil {
		return nil, e
	}
	return &MACState{m}, nil
}
func NewHMAC(key []byte) (*MACState, error) {
	m, e := native.NewBeltMAC(true, key)
	if e != nil {
		return nil, e
	}
	return &MACState{m}, nil
}
func (m *MACState) Write(b []byte) (int, error) { return m.n.Write(b) }
func (m *MACState) Sum(b []byte) []byte         { return m.n.Sum(b) }
func (m *MACState) Reset()                      { m.n.Reset() }
func (m *MACState) Size() int                   { return m.n.Size() }
func (m *MACState) BlockSize() int              { return m.n.BlockSize() }
func (m *MACState) Close() error {
	if m == nil {
		return nil
	}
	return m.n.Close()
}
