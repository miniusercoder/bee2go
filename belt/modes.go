package belt

import "github.com/miniusercoder/bee2go/v3/internal/native"

func ECBEncrypt(src, key []byte) ([]byte, error)     { return native.BeltMode(0, false, src, key, nil) }
func ECBDecrypt(src, key []byte) ([]byte, error)     { return native.BeltMode(0, true, src, key, nil) }
func CBCEncrypt(src, key, iv []byte) ([]byte, error) { return native.BeltMode(1, false, src, key, iv) }
func CBCDecrypt(src, key, iv []byte) ([]byte, error) { return native.BeltMode(1, true, src, key, iv) }
func CFBEncrypt(src, key, iv []byte) ([]byte, error) { return native.BeltMode(2, false, src, key, iv) }
func CFBDecrypt(src, key, iv []byte) ([]byte, error) { return native.BeltMode(2, true, src, key, iv) }
func CTR(src, key, iv []byte) ([]byte, error)        { return native.BeltMode(3, false, src, key, iv) }
func DWPWrap(src, aad, key, iv []byte) ([]byte, []byte, error) {
	return native.BeltAEAD(false, false, src, aad, nil, key, iv)
}
func DWPUnwrap(src, aad, tag, key, iv []byte) ([]byte, error) {
	out, _, e := native.BeltAEAD(false, true, src, aad, tag, key, iv)
	return out, e
}
func CHEWrap(src, aad, key, iv []byte) ([]byte, []byte, error) {
	return native.BeltAEAD(true, false, src, aad, nil, key, iv)
}
func CHEUnwrap(src, aad, tag, key, iv []byte) ([]byte, error) {
	out, _, e := native.BeltAEAD(true, true, src, aad, tag, key, iv)
	return out, e
}
