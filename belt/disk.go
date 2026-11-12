package belt

import "github.com/miniusercoder/bee2go/v3/internal/native"

func BDEEncrypt(src, key, iv []byte) ([]byte, error) {
	return native.BeltDisk(false, false, src, key, iv)
}
func BDEDecrypt(src, key, iv []byte) ([]byte, error) {
	return native.BeltDisk(false, true, src, key, iv)
}
func SDEEncrypt(src, key, iv []byte) ([]byte, error) {
	return native.BeltDisk(true, false, src, key, iv)
}
func SDEDecrypt(src, key, iv []byte) ([]byte, error) {
	return native.BeltDisk(true, true, src, key, iv)
}
func FMTEncrypt(src []uint16, mod uint32, key, iv []byte) ([]uint16, error) {
	return native.BeltFMT(false, src, mod, key, iv)
}
func FMTDecrypt(src []uint16, mod uint32, key, iv []byte) ([]uint16, error) {
	return native.BeltFMT(true, src, mod, key, iv)
}
