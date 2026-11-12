package botp

import (
	bee2 "github.com/miniusercoder/bee2go/v3"
	"github.com/miniusercoder/bee2go/v3/internal/native"
	"regexp"
	"strconv"
	"strings"
)

var suitePattern = regexp.MustCompile(`^OCRA-1:HOTP-HBELT-([4-9]):(C-)?Q([ANH])([0-9]{2})(?:-P(HBELT|SHA1|SHA256|SHA512))?(?:-S([0-9]{3}))?(?:-T([1-9][0-9]?)([SMH]))?$`)

type Suite struct {
	raw                      string
	digits, qmax, plen, slen int
	qtype                    byte
	hasCounter, hasTime      bool
	timeStep                 int
}

func ParseSuite(s string) (Suite, error) {
	var v Suite
	m := suitePattern.FindStringSubmatch(s)
	if m == nil || strings.ContainsRune(s, 0) {
		return v, bee2.ErrInvalidInput
	}
	v.raw = s
	v.digits = int(m[1][0] - '0')
	v.hasCounter = m[2] != ""
	v.qtype = m[3][0]
	v.qmax, _ = strconv.Atoi(m[4])
	if v.qmax < 4 || v.qmax > 64 {
		return Suite{}, bee2.ErrInvalidInput
	}
	switch m[5] {
	case "HBELT", "SHA256":
		v.plen = 32
	case "SHA1":
		v.plen = 20
	case "SHA512":
		v.plen = 64
	}
	if m[6] != "" {
		v.slen, _ = strconv.Atoi(m[6])
		if v.slen > 512 {
			return Suite{}, bee2.ErrInvalidInput
		}
	}
	if m[7] != "" {
		v.hasTime = true
		n, _ := strconv.Atoi(m[7])
		if m[8] == "H" && n > 48 || m[8] != "H" && n > 59 {
			return Suite{}, bee2.ErrInvalidInput
		}
		switch m[8] {
		case "H":
			n *= 3600
		case "M":
			n *= 60
		}
		v.timeStep = n
	}
	return v, nil
}

type OCRA struct {
	state      *native.OCRA
	suite      Suite
	p, session []byte
}

func NewOCRA(s Suite, key []byte, ctr [8]byte, p, session []byte) (*OCRA, error) {
	if s.raw == "" || len(p) != s.plen || len(session) != s.slen {
		return nil, bee2.ErrInvalidInput
	}
	n, e := native.NewOCRA(s.raw, key, ctr, p, session, s.digits, s.qmax, s.qtype, s.hasTime)
	if e != nil {
		return nil, e
	}
	return &OCRA{n, s, append([]byte(nil), p...), append([]byte(nil), session...)}, nil
}
func (o *OCRA) Close() error {
	if o == nil {
		return nil
	}
	native.Wipe(o.p)
	native.Wipe(o.session)
	return o.state.Close()
}
func (o *OCRA) SetCounter(c [8]byte) error                  { return o.state.SetCounter(c, o.p, o.session) }
func (o *OCRA) Counter() ([8]byte, error)                   { return o.state.Counter() }
func (o *OCRA) Next(q string, t int64) (string, error)      { return o.state.Next(q, t) }
func (o *OCRA) Verify(otp, q string, t int64) (bool, error) { return o.state.Verify(otp, q, t) }
func OCRACode(s Suite, key []byte, q string, ctr [8]byte, p, session []byte, step int64) (string, error) {
	o, e := NewOCRA(s, key, ctr, p, session)
	if e != nil {
		return "", e
	}
	defer o.Close()
	return o.state.OneShot(s.raw, key, q, ctr, p, session, step)
}
func VerifyOCRA(otp string, s Suite, key []byte, q string, ctr [8]byte, p, session []byte, step int64) (bool, error) {
	o, e := NewOCRA(s, key, ctr, p, session)
	if e != nil {
		return false, e
	}
	defer o.Close()
	return o.state.VerifyOneShot(otp, s.raw, key, q, ctr, p, session, step)
}

func (s Suite) Digits() int           { return s.digits }
func (s Suite) ChallengeType() byte   { return s.qtype }
func (s Suite) ChallengeMax() int     { return s.qmax }
func (s Suite) HasCounter() bool      { return s.hasCounter }
func (s Suite) PasswordHashSize() int { return s.plen }
func (s Suite) SessionSize() int      { return s.slen }

// TimeStep returns the suite's time step in seconds, or zero when time is absent.
func (s Suite) TimeStep() int { return s.timeStep }
