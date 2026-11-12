package selftest

import (
	"bytes"
	"fmt"
	"github.com/miniusercoder/bee2go/v3/internal/native"
)

// Result records one named diagnostic's outcome.
type Result struct {
	Name string
	Err  error
}
type diagnostic struct {
	name string
	run  func() error
}

func diagnostics() []diagnostic {
	return []diagnostic{{"bpace", SelfTestBPACE}, {"belt-ecb", SelfTestBeltECB}, {"bake-swu", SelfTestBakeSWU}, {"bake-kdf", SelfTestBakeKDF}, {"bign-val-pubkey", SelfTestBignValPubkey}, {"bign-gen-keypair", SelfTestBignGenKeypair}, {"bake-dh", SelfTestBakeDH}, {"belt-hash", SelfTestBeltHash}, {"belt-keyrep", SelfTestBeltKeyrep}, {"brng-ctr-hbel", SelfTestBrngCTRHBEL}}
}

// Run executes every supported diagnostic and reports individual results.
func Run() []Result {
	tests := diagnostics()
	out := make([]Result, 0, len(tests))
	for _, t := range tests {
		out = append(out, Result{t.name, t.run()})
	}
	return out
}

// RunOne executes one named diagnostic. Unknown names return an error.
func RunOne(name string) error {
	for _, t := range diagnostics() {
		if name == t.name {
			return t.run()
		}
	}
	return fmt.Errorf("unknown selftest %q", name)
}

// SelfTestBPACE checks all messages and both keys of the upstream BPACE KAT.
func SelfTestBPACE() error {
	a := mustDecodeHex("AD1362A8F9A3D42FBE1B8E6F1C88AAD50A4E8298BE0839E46F19409F637F4415572251DD0D39284F0F0390D93BBCE9EC")
	defer native.Wipe(a)
	b := mustDecodeHex("0F51D91347617C20BD4AB07AEF4F26A1F81B29D571F6452FF8B2B97F57E18A58BC946FEE45EAB32B06FCAC23A33F422B")
	defer native.Wipe(b)
	out, e := native.KATBPACE(a, b)
	if e != nil {
		return e
	}
	defer func() {
		for _, v := range out {
			native.Wipe(v)
		}
	}()
	want := []string{"991E81690B4C687C86BFD11CEBDA2421", "CE41B54DC13A28BDF74CEBD1908818026B13ACBB086FB87618BCC2EF20A3FA89475654CB367E670A2441730B24B8AB318209C81C9640C47A77B28E90AB9211A1DF21DE878191C314061E347C5125244F", "CD3D6487DC4EEB23456978186A069C71375D75C2DF198BAD1E61EEA0DBBFF7373D1D9ED17A7AD460AA420FB11952D58078BC1CC9F408F2E258FDE97F22A44C6F28FD4859D78BA971", "5D93FD9A7CB863AA", "DAC4D8F411F9C523D28BBAAB32A5270E4DFA1F0F757EF8E0F30AF08FBDE1E7F4"}
	for i, w := range want {
		if e = expectHex(fmt.Sprintf("BPACE %d", i+1), out[i], w); e != nil {
			return e
		}
	}
	if !bytes.Equal(out[4], out[5]) {
		return fmt.Errorf("BPACE keys differ")
	}
	return nil
}
