package stb99

import "testing"

func TestStandardAndSeed(t *testing.T) {
	for _, name := range []string{"test", "1.2.112.0.2.0.1176.2.3.3.1", "1.2.112.0.2.0.1176.2.3.6.1", "1.2.112.0.2.0.1176.2.3.10.1"} {
		p, s, err := Standard(name)
		if err != nil {
			t.Fatal(name, err)
		}
		if err = s.Validate(); err != nil {
			t.Fatal(name, err)
		}
		if err = p.Validate(); err != nil {
			t.Fatal(name, err)
		}
	}
	if _, _, err := Standard("invalid"); err == nil {
		t.Fatal("invalid name accepted")
	}
	s := Seed{L: 638}
	if err := s.Adjust(); err != nil {
		t.Fatal(err)
	}
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	s.DI[4] = 0
	if err := s.Validate(); err == nil {
		t.Fatal("invalid chain accepted")
	}
}
func TestInvalidInputs(t *testing.T) {
	if _, _, e := Standard("test\x00bad"); e == nil {
		t.Fatal("embedded NUL")
	}
	var s *Seed
	if e := s.Adjust(); e == nil {
		t.Fatal("nil seed")
	}
	if _, e := Generate(Seed{}); e == nil {
		t.Fatal("invalid seed")
	}
}
