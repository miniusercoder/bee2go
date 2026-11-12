//go:build slow

package stb99

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
	if got != want {
		t.Fatal("generated parameters differ from upstream")
	}
}
