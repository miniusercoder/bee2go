package belt

import "github.com/miniusercoder/bee2go/v3/internal/native"

func MAC(src, key []byte) ([]byte, error)  { return native.BeltMAC(false, src, key) }
func HMAC(src, key []byte) ([]byte, error) { return native.BeltMAC(true, src, key) }
func KRP(src, level, header []byte, n int) ([]byte, error) {
	return native.BeltKRP(src, level, header, n)
}
func PBKDF2(password []byte, iter int, salt []byte) ([]byte, error) {
	return native.BeltPBKDF2(password, iter, salt)
}
func KWPWrap(src, header, key []byte) ([]byte, error) { return native.BeltKWP(false, src, header, key) }
func KWPUnwrap(src, header, key []byte) ([]byte, error) {
	return native.BeltKWP(true, src, header, key)
}
