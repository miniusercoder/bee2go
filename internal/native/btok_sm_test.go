package native

import "testing"

func TestBTOKSMCounterOverflow(t *testing.T) {
	s, e := NewSecureMessaging(make([]byte, 32))
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	for i := range s.counter {
		s.counter[i] = 255
	}
	if e = s.advance(false); e == nil {
		t.Fatal("counter overflow accepted")
	}
	for _, b := range s.counter {
		if b != 255 {
			t.Fatal("counter changed on overflow")
		}
	}
}
