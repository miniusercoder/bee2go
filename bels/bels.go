// Package bels implements Bee2 secret sharing. Shares are not authenticated.
package bels

import (
	"bytes"
	bee2 "github.com/miniusercoder/bee2go/v3"
	"github.com/miniusercoder/bee2go/v3/internal/native"
	"io"
)

// Params contains a BELS public key in Bee2 byte order.
type Params []byte

// Share owns a partial secret and its associated common/member parameters.
// Metadata prevents accidental parameter substitution; it is not authentication.
// Use Bytes and Parameters when serializing, then NewShare/NewStandardShare
// when importing. Keep the original threshold alongside the shares.
type Share struct {
	value          []byte
	common, member Params
	standard       bool
}

// Bytes returns an owned copy; standard values include their identifier byte.
func (s Share) Bytes() []byte { return bytes.Clone(s.value) }

// Parameters returns owned copies of the common and member public parameters.
func (s Share) Parameters() (common, member Params) {
	return bytes.Clone(s.common), bytes.Clone(s.member)
}

// Identifier reports the standard share number. Custom shares use member Params.
func (s Share) Identifier() (byte, bool) {
	if !s.standard || len(s.value) == 0 {
		return 0, false
	}
	return s.value[0], true
}

// NewShare imports custom share bytes with an explicit parameter association.
// It cannot detect deliberately corrupted share values or forged metadata.
func NewShare(value []byte, common, member Params) (Share, error) {
	if len(value) != len(common) || len(member) != len(common) || bytes.Equal(common, member) {
		return Share{}, bee2.ErrInvalidInput
	}
	if e := Validate(common); e != nil {
		return Share{}, e
	}
	if e := Validate(member); e != nil {
		return Share{}, e
	}
	return Share{value: bytes.Clone(value), common: bytes.Clone(common), member: bytes.Clone(member)}, nil
}
func NewStandardShare(value []byte) (Share, error) {
	n := len(value) - 1
	if (n != 16 && n != 24 && n != 32) || value[0] < 1 || value[0] > 16 {
		return Share{}, bee2.ErrInvalidInput
	}
	common, e := Standard(n, 0)
	if e != nil {
		return Share{}, e
	}
	member, e := Standard(n, int(value[0]))
	if e != nil {
		return Share{}, e
	}
	return Share{value: bytes.Clone(value), common: common, member: member, standard: true}, nil
}
func Standard(length, index int) (Params, error) { return native.BELSStandard(length, index) }
func Validate(m Params) error                    { return native.BELSValidate(m) }
func Derive(m Params, id []byte) (Params, error) { return native.BELSDerive(m, id) }
func GenerateCommon(length int, entropy io.Reader) (Params, error) {
	return native.BELSGenerateCommon(length, entropy)
}
func GenerateMember(common Params, entropy io.Reader) (Params, error) {
	return native.BELSGenerateMember(common, entropy)
}

// ShareDeterministic uses Bee2's experimental deterministic sharing mode.
func ShareDeterministic(secret []byte, count, threshold int) ([]Share, error) {
	s, e := native.BELSShareDeterministic(secret, count, threshold)
	if e != nil {
		return nil, e
	}
	return standardShares(s)
}
func ShareStandard(secret []byte, count, threshold int, entropy io.Reader) ([]Share, error) {
	if count < 0 || count > 16 {
		return nil, bee2.ErrInvalidInput
	}
	s, e := native.BELSShare(secret, nil, make([][]byte, count), threshold, entropy, true)
	if e != nil {
		return nil, e
	}
	return standardShares(s)
}
func Split(secret []byte, common Params, members []Params, threshold int, entropy io.Reader) ([]Share, error) {
	m := make([][]byte, len(members))
	for i := range m {
		m[i] = members[i]
	}
	raw, e := native.BELSShare(secret, common, m, threshold, entropy, false)
	if e != nil {
		return nil, e
	}
	out := make([]Share, len(raw))
	for i := range raw {
		out[i] = Share{value: raw[i], common: bytes.Clone(common), member: bytes.Clone(members[i])}
	}
	return out, nil
}

// Recover rejects parameters that differ from the associations owned by shares.
// Shares themselves remain unauthenticated: corruption may yield another secret.
func Recover(s []Share, common Params, members []Params, threshold int) ([]byte, error) {
	if len(s) != len(members) {
		return nil, bee2.ErrInvalidInput
	}
	m := make([][]byte, len(members))
	for i := range m {
		if s[i].standard || !bytes.Equal(s[i].common, common) || !bytes.Equal(s[i].member, members[i]) {
			return nil, bee2.ErrInvalidInput
		}
		m[i] = members[i]
	}
	return native.BELSRecover(rawShares(s), common, m, threshold)
}
func RecoverStandard(s []Share, threshold int) ([]byte, error) {
	for _, v := range s {
		if !v.standard {
			return nil, bee2.ErrInvalidInput
		}
	}
	return native.BELSRecoverStandard(rawShares(s), threshold)
}
func standardShares(raw [][]byte) ([]Share, error) {
	if raw == nil {
		return nil, nil
	}
	out := make([]Share, len(raw))
	for i := range raw {
		var e error
		out[i], e = NewStandardShare(raw[i])
		if e != nil {
			return nil, e
		}
		native.Wipe(raw[i])
	}
	return out, nil
}
func rawShares(s []Share) [][]byte {
	out := make([][]byte, len(s))
	for i := range s {
		out[i] = s[i].value
	}
	return out
}
