package bee2go

import (
	"errors"
	"testing"
)

func TestNativeErrorCategories(t *testing.T) {
	for _, v := range []struct {
		code   uint32
		target error
	}{{108, ErrInvalidInput}, {502, ErrInvalidInput}, {510, ErrAuthentication}, {511, ErrAuthentication}, {518, ErrAuthentication}, {302, ErrRandom}, {303, ErrRandom}, {517, ErrState}} {
		err := &Error{Op: "test", Code: v.code}
		if !errors.Is(err, v.target) {
			t.Errorf("code %d: %v", v.code, err)
		}
		if errors.Is(err, ErrClosed) {
			t.Error("native error is not closed")
		}
	}
	if errors.Is(&Error{Code: 999}, ErrInvalidInput) {
		t.Fatal("unknown error classified as input")
	}
}
