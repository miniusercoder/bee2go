package belt

import "github.com/miniusercoder/bee2go/v3/internal/native"

type WBL struct{ n *native.BeltWBL }

func NewWBL(key []byte) (*WBL, error) {
	w, e := native.NewBeltWBL(key)
	if e != nil {
		return nil, e
	}
	return &WBL{w}, nil
}
func (w *WBL) Encrypt(b []byte) error  { return w.n.Crypt(b, 0) }
func (w *WBL) Decrypt(b []byte) error  { return w.n.Crypt(b, 1) }
func (w *WBL) Continue(b []byte) error { return w.n.Crypt(b, 2) }
func (w *WBL) Close() error {
	if w == nil {
		return nil
	}
	return w.n.Close()
}

// DecryptSplit decrypts a WBL ciphertext held in disjoint first and last parts.
func (w *WBL) DecryptSplit(first, last []byte) error { return w.n.DecryptSplit(first, last) }
