package bign

import (
	"github.com/miniusercoder/bee2go/v3/internal/native"
	"io"
)

func ExtractIdentity(p *Params, oid, idHash, idCertificate, masterPublic []byte) ([]byte, []byte, error) {
	return native.BignIdExtract(params(p), oid, idHash, idCertificate, masterPublic)
}
func SignIdentityDigest(p *Params, oid, idHash, digest, private []byte, r io.Reader) ([]byte, error) {
	return native.BignIdSign(params(p), oid, idHash, digest, private, r)
}
func SignIdentityDigestDeterministic(p *Params, oid, idHash, digest, private, t []byte) ([]byte, error) {
	return native.BignIdSign2(params(p), oid, idHash, digest, private, t)
}
func VerifyIdentityDigest(p *Params, oid, idHash, digest, sig, identityPublic, masterPublic []byte) error {
	return native.BignIdVerify(params(p), oid, idHash, digest, sig, identityPublic, masterPublic)
}
