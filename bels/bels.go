// Package bels implements Bee2 secret sharing. Shares are not authenticated.
package bels

import (
	bee2 "github.com/miniusercoder/bee2go/v3"
	"github.com/miniusercoder/bee2go/v3/internal/native"
	"io"
)

// Params contains a BELS public key in Bee2 byte order.
type Params []byte

// Share contains a partial secret. Standard shares include the identifier byte.
type Share []byte

func Standard(length, index int) (Params, error) { return native.BELSStandard(length, index) }
func Validate(m Params) error                    { return native.BELSValidate(m) }
func Derive(m Params, id []byte) (Params, error) { return native.BELSDerive(m, id) }

// ShareDeterministic uses Bee2's experimental deterministic sharing mode.
func ShareDeterministic(secret []byte, count, threshold int) ([]Share, error) {
	s, e := native.BELSShareDeterministic(secret, count, threshold)
	return shares(s), e
}

// RecoverStandard requires the original threshold. Shares are not authenticated.
func RecoverStandard(s []Share, threshold int) ([]byte, error) {
	return native.BELSRecoverStandard(rawShares(s), threshold)
}
func GenerateCommon(length int, entropy io.Reader) (Params, error) {
	return native.BELSGenerateCommon(length, entropy)
}
func GenerateMember(common Params, entropy io.Reader) (Params, error) {
	return native.BELSGenerateMember(common, entropy)
}
func Split(secret []byte, common Params, members []Params, threshold int, entropy io.Reader) ([]Share, error) {
	m := make([][]byte, len(members))
	for i := range members {
		m[i] = members[i]
	}
	s, e := native.BELSShare(secret, common, m, threshold, entropy, false)
	return shares(s), e
}
func ShareStandard(secret []byte, count, threshold int, entropy io.Reader) ([]Share, error) {
	if count < 0 || count > 16 {
		return nil, bee2.ErrInvalidInput
	}
	s, e := native.BELSShare(secret, nil, make([][]byte, count), threshold, entropy, true)
	return shares(s), e
}
func Recover(s []Share, common Params, members []Params, threshold int) ([]byte, error) {
	m := make([][]byte, len(members))
	for i := range members {
		m[i] = members[i]
	}
	return native.BELSRecover(rawShares(s), common, m, threshold)
}
func shares(s [][]byte) []Share {
	if s == nil {
		return nil
	}
	out := make([]Share, len(s))
	for i := range s {
		out[i] = Share(s[i])
	}
	return out
}
func rawShares(s []Share) [][]byte {
	out := make([][]byte, len(s))
	for i := range s {
		out[i] = s[i]
	}
	return out
}
