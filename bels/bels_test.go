package bels

import (
	"bytes"
	"encoding/hex"
	"os"
	"strings"
	"testing"
)

func TestStandardAndDerived(t *testing.T) {
	for i, n := range []int{16, 24, 32} {
		for j := 0; j <= 16; j++ {
			m, e := Standard(n, j)
			if e != nil {
				t.Fatal(e)
			}
			if e = Validate(m); e != nil {
				t.Fatal(e)
			}
		}
		m, _ := Standard(n, 0)
		got, e := Derive(m, []byte("Alice"))
		if e != nil {
			t.Fatal(e)
		}
		want, _ := hex.DecodeString([]string{"F9D6F31B5DB0BB61F00E17EEF2E6007F", "09EA79297F94A3E43A3885FC0D1BB8FDD0DF86FD313CEF46", "D53CC51BE1F976F1032A00D9CD0E190E62C37FFD233E8A9DF14C85F85C51A045"}[i])
		if !bytes.Equal(got, want) {
			t.Fatalf("%x", got)
		}
	}
	if _, e := Standard(15, 0); e == nil {
		t.Fatal("length")
	}
	if _, e := Standard(16, 17); e == nil {
		t.Fatal("index")
	}
	if e := Validate(make([]byte, 16)); e == nil {
		t.Fatal("invalid key")
	}
}
func TestShares(t *testing.T) {
	for _, n := range []int{16, 24, 32} {
		secret := bytes.Repeat([]byte{42}, n)
		shares, e := ShareDeterministic(secret, 5, 3)
		if e != nil {
			t.Fatal(e)
		}
		for _, set := range [][]int{{0, 1, 2}, {0, 2, 4}, {1, 2, 3, 4}} {
			var selected []Share
			for _, i := range set {
				selected = append(selected, shares[i])
			}
			got, e := RecoverStandard(selected, 3)
			if e != nil || !bytes.Equal(got, secret) {
				t.Fatalf("%x %v", got, e)
			}
		}
		if _, e = RecoverStandard(shares[:2], 3); e == nil {
			t.Fatal("threshold")
		}
		if _, e = RecoverStandard([]Share{shares[0], shares[0], shares[1]}, 3); e == nil {
			t.Fatal("duplicate")
		}
	}
}
func TestRandomAndCustom(t *testing.T) {
	for _, n := range []int{16, 24, 32} {
		common, e := GenerateCommon(n, nil)
		if e != nil {
			t.Fatal(e)
		}
		if e = Validate(common); e != nil {
			t.Fatal(e)
		}
		member, e := GenerateMember(common, nil)
		if e != nil {
			t.Fatal(e)
		}
		if e = Validate(member); e != nil {
			t.Fatal(e)
		}
		common, _ = Standard(n, 0)
		var members []Params
		for i := 1; i <= 5; i++ {
			m, _ := Standard(n, i)
			members = append(members, m)
		}
		secret := bytes.Repeat([]byte{42}, n)
		shares, e := Split(secret, common, members, 3, nil)
		if e != nil {
			t.Fatal(e)
		}
		got, e := Recover(shares[:3], common, members[:3], 3)
		if e != nil || !bytes.Equal(got, secret) {
			t.Fatal(e)
		}
		std, e := ShareStandard(secret, 5, 3, nil)
		if e != nil {
			t.Fatal(e)
		}
		got, e = RecoverStandard(std[:3], 3)
		if e != nil || !bytes.Equal(got, secret) {
			t.Fatal(e)
		}
	}
}
func TestRandomErrors(t *testing.T) {
	if _, e := GenerateCommon(16, bytes.NewReader(nil)); e == nil {
		t.Fatal("entropy")
	}
	if _, e := ShareStandard(make([]byte, 16), 2, 3, nil); e == nil {
		t.Fatal("threshold")
	}
	m, _ := Standard(16, 0)
	a, _ := Standard(16, 1)
	if _, e := Split(make([]byte, 16), m, []Params{a, a}, 2, nil); e == nil {
		t.Fatal("duplicate member")
	}
	if _, e := Derive(make([]byte, 16), []byte("id")); e == nil {
		t.Fatal("invalid common")
	}
}
func TestCustomParametersRejected(t *testing.T) {
	common, _ := Standard(16, 0)
	a, _ := Standard(16, 1)
	b, _ := Standard(16, 2)
	secret := make([]byte, 16)
	shares, e := Split(secret, common, []Params{a, b}, 2, nil)
	if e != nil {
		t.Fatal(e)
	}
	for _, bad := range []Params{make([]byte, 16), common} {
		if _, e = Split(secret, common, []Params{a, bad}, 2, nil); e == nil {
			t.Fatal("accepted invalid member")
		}
		if _, e = Recover(shares, common, []Params{a, bad}, 2); e == nil {
			t.Fatal("accepted invalid recovery member")
		}
	}
	if _, e = Recover(shares, common, []Params{a, a}, 2); e == nil {
		t.Fatal("accepted duplicate member")
	}
}
func TestUpstreamRecoveryVector(t *testing.T) {
	secret, _ := hex.DecodeString("B194BAC80A08F53B366D008E584A5DE4")
	raw, _ := hex.DecodeString("E27D0CFD31C557BC37C3897DCFF2C7FC50BB9EECBAEF52DDB811BCDE1495441DA92473F6796683534AD115812A3F99509A8331FD945D58E6D8723E4744FB1DA951913D18C8625C5AB0812133FB643D66")
	common, _ := Standard(16, 0)
	shares := make([]Share, 5)
	members := make([]Params, 5)
	for i := range shares {
		shares[i] = Share(raw[i*16 : (i+1)*16])
		members[i], _ = Standard(16, i+1)
	}
	got, e := Recover([]Share{shares[0], shares[2], shares[4]}, common, []Params{members[0], members[2], members[4]}, 3)
	if e != nil || !bytes.Equal(got, secret) {
		t.Fatalf("%x %v", got, e)
	}
	got, e = Recover(shares[:2], common, members[:2], 2)
	expected, _ := hex.DecodeString("6380669CA508058FA9AADF986C77C175")
	if e != nil || !bytes.Equal(got, expected) {
		t.Fatalf("%x %v", got, e)
	}
}
func TestShareCVectors(t *testing.T) {
	raw, e := os.ReadFile("testdata/vectors.txt")
	if e != nil {
		t.Fatal(e)
	}
	vectors := strings.Fields(string(raw))
	if len(vectors) != 6 {
		t.Fatal("missing C vectors")
	}
	h, _ := hex.DecodeString("B194BAC80A08F53B366D008E584A5DE48504FA9D1BB6C7AC252E72C202FDCE0D")
	seed, _ := hex.DecodeString("E9DEE72C8F0C0FA62DDB49F46F73964706075316ED247A3739CBA38303A98BF692BD9B1CE5D141015445FBC95E4D0EF2682080AA227D642F2687F93490405511")
	for i, n := range []int{16, 24, 32} {
		common, _ := Standard(n, 0)
		members := make([]Params, 5)
		for j := range members {
			members[j], _ = Standard(n, j+1)
		}
		shares, e := Split(h[:n], common, members, 3, bytes.NewReader(seed))
		if e != nil {
			t.Fatal(e)
		}
		var combined []byte
		for _, s := range shares {
			combined = append(combined, s...)
		}
		want, _ := hex.DecodeString(vectors[2*i])
		if !bytes.Equal(combined, want) {
			t.Fatalf("custom %d: %x", n, combined)
		}
		standard, e := ShareStandard(h[:n], 5, 3, bytes.NewReader(seed))
		if e != nil {
			t.Fatal(e)
		}
		combined = nil
		for _, s := range standard {
			combined = append(combined, s...)
		}
		want, _ = hex.DecodeString(vectors[2*i+1])
		if !bytes.Equal(combined, want) {
			t.Fatalf("standard %d: %x", n, combined)
		}
	}
}

func TestParameterAndDeterministicShareCVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/remaining_vectors.txt")
	if err != nil {
		t.Fatal(err)
	}
	vectors := strings.Fields(string(raw))
	if len(vectors) != 9 {
		t.Fatalf("got %d C vectors, want 9", len(vectors))
	}
	seed, err := hex.DecodeString("E9DEE72C8F0C0FA62DDB49F46F73964706075316ED247A3739CBA38303A98BF692BD9B1CE5D141015445FBC95E4D0EF2682080AA227D642F2687F93490405511")
	if err != nil {
		t.Fatal(err)
	}
	secret, err := hex.DecodeString("B194BAC80A08F53B366D008E584A5DE48504FA9D1BB6C7AC252E72C202FDCE0D")
	if err != nil {
		t.Fatal(err)
	}
	for i, length := range []int{16, 24, 32} {
		expectedCommon, err := hex.DecodeString(vectors[3*i])
		if err != nil {
			t.Fatal(err)
		}
		gotCommon, err := GenerateCommon(length, bytes.NewReader(seed))
		if err != nil || !bytes.Equal(gotCommon, expectedCommon) {
			t.Fatalf("GenerateCommon(%d): %x, %v", length, gotCommon, err)
		}
		common, err := Standard(length, 0)
		if err != nil {
			t.Fatal(err)
		}
		expectedMember, err := hex.DecodeString(vectors[3*i+1])
		if err != nil {
			t.Fatal(err)
		}
		gotMember, err := GenerateMember(common, bytes.NewReader(seed))
		if err != nil || !bytes.Equal(gotMember, expectedMember) {
			t.Fatalf("GenerateMember(%d): %x, %v", length, gotMember, err)
		}
		expectedShares, err := hex.DecodeString(vectors[3*i+2])
		if err != nil {
			t.Fatal(err)
		}
		shares, err := ShareDeterministic(secret[:length], 5, 3)
		if err != nil {
			t.Fatal(err)
		}
		var gotShares []byte
		for _, share := range shares {
			gotShares = append(gotShares, share...)
		}
		if !bytes.Equal(gotShares, expectedShares) {
			t.Fatalf("ShareDeterministic(%d): %x", length, gotShares)
		}
	}
}
