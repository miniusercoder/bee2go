package bee2go

import (
	"errors"
	"fmt"
)

var (
	ErrInvalidInput   = errors.New("bee2: invalid input")
	ErrAuthentication = errors.New("bee2: authentication failed")
	ErrRandom         = errors.New("bee2: entropy unavailable")
	ErrClosed         = errors.New("bee2: object closed")
	ErrState          = errors.New("bee2: invalid state")
)

// Error preserves the upstream error code without including secret inputs.
type Error struct {
	Op   string
	Code uint32
}

func (e *Error) Error() string { return fmt.Sprintf("bee2: %s: error %d", e.Op, e.Code) }

// Is classifies upstream errors. Unknown codes remain inspectable with errors.As.
func (e *Error) Is(target error) bool {
	switch e.Code {
	case 302, 303, 304:
		return target == ErrRandom
	case 507, 510, 511, 512, 513, 514, 515, 516, 518, 520, 521:
		return target == ErrAuthentication
	case 115, 116, 517:
		return target == ErrState
	case 108, 109, 111, 301, 305, 306, 307, 308, 309, 310, 311, 312, 401, 402, 403, 404, 501, 502, 503, 504, 505, 506, 508, 509, 524:
		return target == ErrInvalidInput
	}
	return false
}
