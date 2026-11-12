//go:build slow

package pfok

import "testing"

func TestGenerateUpstream(t *testing.T) {
	want, seed, e := Standard("test")
	if e != nil {
		t.Fatal(e)
	}
	got, e := Generate(seed)
	if e != nil {
		t.Fatal(e)
	}
	if got.L != want.L || got.R != want.R || got.N != want.N || got.P != want.P {
		t.Fatal("generated parameters differ from upstream")
	}
	if e = got.Validate(); e != nil {
		t.Fatal(e)
	}
}
func TestGenerateProgress(t *testing.T) {
	_, seed, e := Standard("test")
	if e != nil {
		t.Fatal(e)
	}
	calls := 0
	_, e = GenerateWithProgress(seed, func(q []byte, attempt uint64) {
		if len(q) == 0 {
			t.Error("empty q")
		}
		calls++
	})
	if e != nil {
		t.Fatal(e)
	}
	if calls == 0 {
		t.Fatal("no callbacks")
	}
}
func TestProgressPanic(t *testing.T) {
	_, seed, e := Standard("test")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = GenerateWithProgress(seed, func([]byte, uint64) { panic("callback") }); e == nil {
		t.Fatal("panic not reported")
	}
}
