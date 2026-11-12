package selftest

import "testing"

func TestDiagnostics(t *testing.T) {
	want := map[string]bool{"bpace": true, "belt-ecb": true, "bake-swu": true, "bake-kdf": true, "bign-val-pubkey": true, "bign-gen-keypair": true, "bake-dh": true, "belt-hash": true, "belt-keyrep": true, "brng-ctr-hbel": true}
	results := Run()
	if len(results) != len(want) {
		t.Fatalf("got %d diagnostics", len(results))
	}
	for _, r := range results {
		if !want[r.Name] {
			t.Errorf("unexpected or duplicate %q", r.Name)
		}
		delete(want, r.Name)
		if r.Err != nil {
			t.Errorf("%s: %v", r.Name, r.Err)
		}
	}
	if len(want) != 0 {
		t.Fatalf("missing: %v", want)
	}
	if err := RunOne("nonexistent"); err == nil {
		t.Fatal("unknown test accepted")
	}
}
