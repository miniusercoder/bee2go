package belt

import "github.com/miniusercoder/bee2go/v3/internal/native"

// Block implements cipher.Block. Close wipes the expanded key.
type Block struct{ n *native.BeltBlock }

func NewBlock(key []byte) (*Block, error) {
	b, e := native.NewBeltBlock(key)
	if e != nil {
		return nil, e
	}
	return &Block{b}, nil
}
func (b *Block) BlockSize() int          { return b.n.BlockSize() }
func (b *Block) Encrypt(dst, src []byte) { b.n.Crypt(dst, src, false) }
func (b *Block) Decrypt(dst, src []byte) { b.n.Crypt(dst, src, true) }
func (b *Block) Close() error {
	if b == nil {
		return nil
	}
	return b.n.Close()
}
