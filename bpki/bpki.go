// Package bpki implements Bee2 private-key, share, and CSR containers.
package bpki

import "github.com/miniusercoder/bee2go/v3/internal/native"

// Protection contains the password and PBKDF2 parameters used for a container.
type Protection struct {
	Password   []byte
	Salt       []byte
	Iterations int
}

// WrapPrivateKey protects a 24, 32, 48, or 64-byte private key.
func WrapPrivateKey(key []byte, protection Protection) ([]byte, error) {
	return native.BPKIWrap(key, protection.Password, protection.Salt, protection.Iterations, false)
}
func UnwrapPrivateKey(der, password []byte) ([]byte, error) {
	return native.BPKIUnwrap(der, password, false)
}

// WrapShare protects a standard BELS share with its one-byte key identifier.
func WrapShare(share []byte, protection Protection) ([]byte, error) {
	return native.BPKIWrap(share, protection.Password, protection.Salt, protection.Iterations, true)
}
func UnwrapShare(der, password []byte) ([]byte, error) { return native.BPKIUnwrap(der, password, true) }

// RewrapCSR reissues an existing CSR using a 32-byte private key.
func RewrapCSR(csr, key []byte) ([]byte, error) { return native.BPKIRewrapCSR(csr, key) }
func UnwrapCSR(csr []byte) ([]byte, error)      { return native.BPKIUnwrapCSR(csr) }
