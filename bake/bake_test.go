package bake

import (
	"bytes"
	"errors"
	bee2 "github.com/miniusercoder/bee2go/v3"
	"github.com/miniusercoder/bee2go/v3/bign"
	"sync"
	"testing"
)

func setup(t *testing.T) (*bign.Params, []byte, []byte, []byte, []byte, CertValidator) {
	t.Helper()
	p, e := bign.StandardParams(bign.Curve256v1)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { p.Close() })
	a, A, e := bign.GenerateKey(p, nil)
	if e != nil {
		t.Fatal(e)
	}
	b, B, e := bign.GenerateKey(p, nil)
	if e != nil {
		t.Fatal(e)
	}
	val := func(der, cert []byte) ([]byte, error) {
		switch string(cert) {
		case "Alice":
			return A, nil
		case "Bob":
			return B, nil
		}
		return nil, errors.New("untrusted certificate")
	}
	return p, a, b, []byte("Alice"), []byte("Bob"), val
}
func TestBSTSAndState(t *testing.T) {
	p, a, b, ca, cb, v := setup(t)
	s := Settings{ConfirmA: true, ConfirmB: true}
	A, e := NewBSTS(p, RoleA, s, a, Certificate{ca, v})
	if e != nil {
		t.Fatal(e)
	}
	defer A.Close()
	B, e := NewBSTS(p, RoleB, s, b, Certificate{cb, v})
	if e != nil {
		t.Fatal(e)
	}
	defer B.Close()
	if key, e := A.Key(); key != nil || !errors.Is(e, bee2.ErrState) {
		t.Fatal(e)
	}
	m1, e := B.Step2()
	if e != nil {
		t.Fatal(e)
	}
	m2, e := A.Step3(m1)
	if e != nil {
		t.Fatal(e)
	}
	m3, e := B.Step4(m2, v)
	if e != nil {
		t.Fatal(e)
	}
	if e = A.Step5(m3, v); e != nil {
		t.Fatal(e)
	}
	ka, e := A.Key()
	if e != nil {
		t.Fatal(e)
	}
	kb, e := B.Key()
	if e != nil || !bytes.Equal(ka, kb) {
		t.Fatal(e)
	}
	A.Close()
	A.Close()
	if _, e = A.Key(); !errors.Is(e, bee2.ErrClosed) {
		t.Fatal(e)
	}
}
func TestBMQVAndBPACEConfirmations(t *testing.T) {
	for _, ka := range []bool{false, true} {
		for _, kb := range []bool{false, true} {
			p, a, b, ca, cb, v := setup(t)
			s := Settings{ConfirmA: ka, ConfirmB: kb}
			A, e := NewBMQV(p, RoleA, s, a, Certificate{ca, v})
			if e != nil {
				t.Fatal(e)
			}
			defer A.Close()
			B, e := NewBMQV(p, RoleB, s, b, Certificate{cb, v})
			if e != nil {
				t.Fatal(e)
			}
			defer B.Close()
			m1, e := B.Step2()
			if e != nil {
				t.Fatal(e)
			}
			m2, e := A.Step3(m1, Certificate{cb, v})
			if e != nil {
				t.Fatal(e)
			}
			m3, e := B.Step4(m2, Certificate{ca, v})
			if e != nil {
				t.Fatal(e)
			}
			if kb {
				if e = A.Step5(m3); e != nil {
					t.Fatal(e)
				}
			}
			x, e := A.Key()
			if e != nil {
				t.Fatal(e)
			}
			y, e := B.Key()
			if e != nil || !bytes.Equal(x, y) {
				t.Fatal(e)
			}
			C, e := NewBPACE(p, RoleA, s, []byte("password"))
			if e != nil {
				t.Fatal(e)
			}
			defer C.Close()
			D, e := NewBPACE(p, RoleB, s, []byte("password"))
			if e != nil {
				t.Fatal(e)
			}
			defer D.Close()
			m1, e = D.Step2()
			if e != nil {
				t.Fatal(e)
			}
			m2, e = C.Step3(m1)
			if e != nil {
				t.Fatal(e)
			}
			m3, e = D.Step4(m2)
			if e != nil {
				t.Fatal(e)
			}
			m4, e := C.Step5(m3)
			if e != nil {
				t.Fatal(e)
			}
			if ka {
				if e = D.Step6(m4); e != nil {
					t.Fatal(e)
				}
			}
			x, e = C.Key()
			if e != nil {
				t.Fatal(e)
			}
			y, e = D.Key()
			if e != nil || !bytes.Equal(x, y) {
				t.Fatal(e)
			}
		}
	}
}
func TestParallelAndNestedCertificateCallbacks(t *testing.T) {
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p, a, _, ca, _, v := setup(t)
			s := Settings{ConfirmA: true, ConfirmB: true}
			nested := func(der, cert []byte) ([]byte, error) {
				n, e := NewBSTS(p, RoleB, s, a, Certificate{ca, v})
				if e != nil {
					return nil, e
				}
				n.Close()
				return v(der, cert)
			}
			A, e := NewBSTS(p, RoleA, s, a, Certificate{ca, nested})
			if e != nil {
				t.Error(e)
				return
			}
			A.Close()
		}()
	}
	wg.Wait()
}
func TestValidatorPanic(t *testing.T) {
	p, a, _, ca, _, _ := setup(t)
	s := Settings{ConfirmA: true, ConfirmB: true}
	if a, e := NewBSTS(p, RoleA, s, a, Certificate{ca, func([]byte, []byte) ([]byte, error) { panic("test") }}); a != nil || !errors.Is(e, bee2.ErrAuthentication) {
		t.Fatal(e)
	}
}
func TestValidatorCannotCloseActiveSession(t *testing.T) {
	p, a, b, ca, cb, v := setup(t)
	settings := Settings{ConfirmA: true, ConfirmB: true}
	A, e := NewBMQV(p, RoleA, settings, a, Certificate{ca, v})
	if e != nil {
		t.Fatal(e)
	}
	defer A.Close()
	B, e := NewBMQV(p, RoleB, settings, b, Certificate{cb, v})
	if e != nil {
		t.Fatal(e)
	}
	defer B.Close()
	m1, e := B.Step2()
	if e != nil {
		t.Fatal(e)
	}
	var closeErr error
	nested := func(der, cert []byte) ([]byte, error) { closeErr = A.Close(); return v(der, cert) }
	if _, e = A.Step3(m1, Certificate{cb, nested}); e != nil {
		t.Fatal(e)
	}
	if !errors.Is(closeErr, bee2.ErrState) {
		t.Fatalf("Close during C callback must reject, got %v", closeErr)
	}
}
func TestKDFSWUDHInvalidInputs(t *testing.T) {
	p, a, b, _, _, _ := setup(t)
	pub, e := bign.PublicKey(p, b)
	if e != nil {
		t.Fatal(e)
	}
	if out, e := KDF(nil, nil, -1); out != nil || !errors.Is(e, bee2.ErrInvalidInput) {
		t.Fatal(e)
	}
	for _, n := range []int{0, 31, 33} {
		if out, e := SWU(p, make([]byte, n)); out != nil || !errors.Is(e, bee2.ErrInvalidInput) {
			t.Fatal(e)
		}
	}
	if out, e := SWU(nil, make([]byte, 32)); out != nil || !errors.Is(e, bee2.ErrInvalidInput) {
		t.Fatal(e)
	}
	for _, n := range []int{-1, 65} {
		if out, e := DH(p, a, pub, n); out != nil || !errors.Is(e, bee2.ErrInvalidInput) {
			t.Fatal(e)
		}
	}
	p.Close()
	if out, e := SWU(p, make([]byte, 32)); out != nil || !errors.Is(e, bee2.ErrClosed) {
		t.Fatal(e)
	}
	if out, e := DH(p, a, pub, 32); out != nil || !errors.Is(e, bee2.ErrClosed) {
		t.Fatal(e)
	}
}
