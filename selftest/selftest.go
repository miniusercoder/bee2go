// Package selftest runs diagnostic known-answer tests for selected bee2 algorithms.
// Passing these checks is not a certification of a deployment.
package selftest

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/miniusercoder/bee2go/v3/bake"
	"github.com/miniusercoder/bee2go/v3/belt"
	"github.com/miniusercoder/bee2go/v3/bign"
	"github.com/miniusercoder/bee2go/v3/brng"
	"github.com/miniusercoder/bee2go/v3/internal/native"
	"strings"
)

// SelfTestBeltECB runs the STB 34.101.31 belt-ECB KATs A.9 and A.10.
func SelfTestBeltECB() error {
	h := beltHBytes()
	defer native.Wipe(h)
	keyE := h[128:160]
	keyD := h[160:192]

	enc48, err := belt.ECBEncrypt(h[:48], keyE)
	defer native.Wipe(enc48)
	if err != nil {
		return err
	}
	if err := expectHex("belt-ECB A.9-1", enc48, "69CCA1C93557C9E3D66BC3E0FA88FA6E5F23102EF109710775017F73806DA9DC46FB2ED2CE771F26DCB5E5D1569F9AB0"); err != nil {
		return err
	}
	dec48, err := belt.ECBDecrypt(enc48, keyE)
	defer native.Wipe(dec48)
	if err != nil {
		return err
	}
	if !bytes.Equal(dec48, h[:48]) {
		return fmt.Errorf("belt-ECB A.9-1 decrypt mismatch")
	}

	enc47, err := belt.ECBEncrypt(h[:47], keyE)
	defer native.Wipe(enc47)
	if err != nil {
		return err
	}
	if err := expectHex("belt-ECB A.9-2", enc47, "69CCA1C93557C9E3D66BC3E0FA88FA6E36F00CFED6D1CA1498C12798F4BEB2075F23102EF109710775017F73806DA9"); err != nil {
		return err
	}
	dec47, err := belt.ECBDecrypt(enc47, keyE)
	defer native.Wipe(dec47)
	if err != nil {
		return err
	}
	if !bytes.Equal(dec47, h[:47]) {
		return fmt.Errorf("belt-ECB A.9-2 decrypt mismatch")
	}

	got, err := belt.ECBDecrypt(h[64:112], keyD)
	defer native.Wipe(got)
	if err != nil {
		return err
	}
	if err := expectHex("belt-ECB A.10-1", got, "0DC5300600CAB840B38448E5E993F421E55A239F2AB5C5D5FDB6E81B40938E2A54120CA3E6E19C7AD750FC3531DAEAB7"); err != nil {
		return err
	}
	native.Wipe(got)
	got, err = belt.ECBDecrypt(h[64:100], keyD)
	if err != nil {
		return err
	}
	return expectHex("belt-ECB A.10-2", got, "0DC5300600CAB840B38448E5E993F4215780A6E2B69EAFBB258726D7B6718523E55A239F")
}

// SelfTestBakeSWU runs the bakeSWU KAT from STB 34.101.66 appendix B.4 data.
func SelfTestBakeSWU() error {
	params, err := bign.StandardParams("1.2.112.0.2.0.34.101.45.3.1")
	if err != nil {
		return err
	}
	defer params.Close()
	msg := mustDecodeHex("AD1362A8F9A3D42FBE1B8E6F1C88AAD50F51D91347617C20BD4AB07AEF4F26A1")
	defer native.Wipe(msg)
	pt, err := bake.SWU(params, msg)
	defer native.Wipe(pt)
	if err != nil {
		return err
	}
	return expectHex("bakeSWU", pt, "014417D3355557317D2E2AB6D08754878D19E8D97B71FDC95DBB2A9B894D16D77704A0B5CAA9CDA10791E4760671E1050DDEAB7083A7458447866ADB01473810")
}

// SelfTestBakeKDF runs the bakeKDF KAT from STB 34.101.66 appendix B.4 data.
func SelfTestBakeKDF() error {
	secret := mustDecodeHex("723356E335ED70620FFB1842752092C32603EB666040920587D800575BECFC42")
	iv := mustDecodeHex("6B13ACBB086FB87618BCC2EF20A3FA89475654CB367E670A2441730B24B8AB31CD3D6487DC4EEB23456978186A069C71375D75C2DF198BAD1E61EEA0DBBFF737")
	defer native.Wipe(secret)
	defer native.Wipe(iv)
	key0, err := bake.KDF(secret, iv, 0)
	defer native.Wipe(key0)
	if err != nil {
		return err
	}
	if err := expectHex("bakeKDF num=0", key0, "DAC4D8F411F9C523D28BBAAB32A5270E4DFA1F0F757EF8E0F30AF08FBDE1E7F4"); err != nil {
		return err
	}
	key1, err := bake.KDF(secret, iv, 1)
	defer native.Wipe(key1)
	if err != nil {
		return err
	}
	return expectHex("bakeKDF num=1", key1, "54AC058284D679CF4C47D3D72651F3E4EF0D61D1D0ED5BAF8FF30B8924E599D8")
}

// SelfTestBignValPubkey validates the bign public key from STB 34.101.45 G.1.
func SelfTestBignValPubkey() error {
	params, err := bign.StandardParams("1.2.112.0.2.0.34.101.45.3.1")
	if err != nil {
		return err
	}
	defer params.Close()
	pub := mustDecodeHex("BD1A5650179D79E03FCEE49D4C2BD5DDF54CE46D0CF11E4FF87BF7A890857FD07AC6A60361E8C8173491686D461B2826190C2EDA5909054A9AB84D2AB9D99A90")
	defer native.Wipe(pub)
	if err := bign.ValidatePublicKey(params, pub); err != nil {
		return err
	}
	bad := make([]byte, len(pub))
	defer native.Wipe(bad)
	copy(bad, pub)
	bad[0] ^= 0xFF
	if err := bign.ValidatePublicKey(params, bad); err == nil {
		return fmt.Errorf("corrupted bign public key was accepted")
	}
	if err := bign.ValidatePublicKey(params, make([]byte, 64)); err == nil {
		return fmt.Errorf("zero bign public key was accepted")
	}
	return nil
}

// SelfTestBignGenKeypair runs the deterministic bign keypair KAT G.1.
func SelfTestBignGenKeypair() error {
	params, err := bign.StandardParams("1.2.112.0.2.0.34.101.45.3.1")
	if err != nil {
		return err
	}
	defer params.Close()
	priv, pub, err := native.KATBignKeypair()
	defer native.Wipe(priv)
	defer native.Wipe(pub)
	if err != nil {
		return err
	}
	if err := expectHex("bign privkey", priv, "1F66B5B84B7339674533F0329C74F21834281FED0732429E0C79235FC273E269"); err != nil {
		return err
	}
	if err := expectHex("bign pubkey", pub, "BD1A5650179D79E03FCEE49D4C2BD5DDF54CE46D0CF11E4FF87BF7A890857FD07AC6A60361E8C8173491686D461B2826190C2EDA5909054A9AB84D2AB9D99A90"); err != nil {
		return err
	}
	if err := bign.ValidatePublicKey(params, pub); err != nil {
		return err
	}
	pub2, err := bign.PublicKey(params, priv)
	defer native.Wipe(pub2)
	if err != nil {
		return err
	}
	if !bytes.Equal(pub, pub2) {
		return fmt.Errorf("bignPubkeyCalc mismatch")
	}
	return nil
}

// SelfTestBakeDH verifies bakeDH as the bignDH alias, including the upstream
// generator-point KAT.
func SelfTestBakeDH() error {
	params, err := bign.StandardParams("1.2.112.0.2.0.34.101.45.3.1")
	if err != nil {
		return err
	}
	defer params.Close()
	priv := mustDecodeHex("1F66B5B84B7339674533F0329C74F21834281FED0732429E0C79235FC273E269")
	defer native.Wipe(priv)
	shared, err := native.KATBakeDH(priv)
	defer native.Wipe(shared)
	if err != nil {
		return err
	}
	if err := expectHex("bakeDH generator KAT", shared, "BD1A5650179D79E03FCEE49D4C2BD5DDF54CE46D0CF11E4FF87BF7A890857FD07AC6A60361E8C8173491686D461B2826190C2EDA5909054A9AB84D2AB9D99A90"); err != nil {
		return err
	}

	privA, pubA, err := bign.GenerateKey(params, nil)
	defer native.Wipe(privA)
	defer native.Wipe(pubA)
	if err != nil {
		return err
	}
	privB, pubB, err := bign.GenerateKey(params, nil)
	defer native.Wipe(privB)
	defer native.Wipe(pubB)
	if err != nil {
		return err
	}
	keyA, err := bake.DH(params, privA, pubB, 32)
	defer native.Wipe(keyA)
	if err != nil {
		return err
	}
	keyB, err := bake.DH(params, privB, pubA, 32)
	defer native.Wipe(keyB)
	if err != nil {
		return err
	}
	if !bytes.Equal(keyA, keyB) {
		return fmt.Errorf("bakeDH symmetry mismatch")
	}
	return nil
}

// SelfTestBeltHash runs the STB 34.101.31 belt-hash KATs A.23.
func SelfTestBeltHash() error {
	h := beltHBytes()
	defer native.Wipe(h)
	cases := []struct {
		n    int
		want string
	}{
		{13, "ABEF9725D4C5A83597A367D14494CC2542F20F659DDFECC961A3EC550CBA8C75"},
		{32, "749E4C3653AECE5E48DB4761227742EB6DBE13F4A80F7BEFF1A9CF8D10EE7786"},
		{48, "9D02EE446FB6A29FE5C982D4B13AF9D3E90861BC4CEF27CF306BFB0B174A154A"},
	}
	for _, tc := range cases {
		got, err := belt.Hash(h[:tc.n])
		defer native.Wipe(got)
		if err != nil {
			return err
		}
		if err := expectHex(fmt.Sprintf("belt-hash n=%d", tc.n), got, tc.want); err != nil {
			return err
		}
		expected := mustDecodeHex(tc.want)
		defer native.Wipe(expected)
		ok, err := belt.HashVerify(h[:tc.n], expected)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("belt-hash verify failed for n=%d", tc.n)
		}
	}
	prefix, err := belt.HashN(h[:32], 13)
	defer native.Wipe(prefix)
	if err != nil {
		return err
	}
	return expectHex("belt-hash prefix", prefix, "749E4C3653AECE5E48DB476122")
}

// SelfTestBeltKeyrep runs the STB 34.101.31 belt-keyrep KATs A.28.
func SelfTestBeltKeyrep() error {
	h := beltHBytes()
	defer native.Wipe(h)
	level := make([]byte, 12)
	defer native.Wipe(level)
	level[0] = 1
	header := h[32:48]
	src := h[128:160]
	cases := []struct {
		m    int
		want string
	}{
		{16, "6BBBC2336670D31AB83DAA90D52C0541"},
		{24, "9A2532A18CBAF145398D5A95FEEA6C825B9C197156A00275"},
		{32, "76E166E6AB21256B6739397B672B879614B81CF05955FC3AB09343A745C48F77"},
	}
	for _, tc := range cases {
		got, err := belt.KRP(src, level, header, tc.m)
		defer native.Wipe(got)
		if err != nil {
			return err
		}
		if err := expectHex(fmt.Sprintf("belt-keyrep m=%d", tc.m), got, tc.want); err != nil {
			return err
		}
	}
	return nil
}

// SelfTestBrngCTRHBEL runs the STB 34.101.47 brng-CTR-hbelt KAT B.2.
func SelfTestBrngCTRHBEL() error {
	h := beltHBytes()
	defer native.Wipe(h)
	key := h[128:160]
	iv := h[192:224]

	r, err := brng.NewCTR(key, iv)
	if err != nil {
		return err
	}
	defer r.Close()
	buf := beltHBytes()
	defer native.Wipe(buf)
	for _, chunk := range [][]byte{buf[:32], buf[32:64], buf[64:96]} {
		if err := r.Transform(chunk); err != nil {
			return err
		}
	}
	gotIV, err := r.IV()
	if err != nil {
		return err
	}
	defer native.Wipe(gotIV)
	if err := expectHex("brng-CTR updated IV", gotIV, "C132971343FC9A48A02A885F194B09A17ECDA4D01544AF8CA58450BF66D2E88A"); err != nil {
		return err
	}
	if err := r.Transform(buf[96:]); err != nil {
		return err
	}
	if err := expectHex("brng-CTR stream", buf, "1F66B5B84B7339674533F0329C74F21834281FED0732429E0C79235FC273E2694C0E74B2CD5811AD21F23DE7E0FA742C3ED6EC483C461CE15C33A77AA308B7D20F51D91347617C20BD4AB07AEF4F26A1AD1362A8F9A3D42FBE1B8E6F1C88AAD50A4E8298BE0839E46F19409F637F4415572251DD0D39284F0F0390D93BBCE9ECF81B29D571F6452FF8B2B97F57E18A58BC946FEE45EAB32B06FCAC23A33F422BC431B41BBE8E802288737ACF45A29251FC736A3C6F478F77A7ED271D5EEDAA58E98309303623AFD33017C42BC6D43C15438446EE57D46E412EFC0B61B5FBA39ED37BABE50BFEEB8ED162BB1393D46FB43534A201EB3B1A5C085DC5068ED6F89A"); err != nil {
		return err
	}

	h1 := beltHBytes()
	defer native.Wipe(h1)
	buf1 := h1[:96]
	iv1, err := brng.CTRTransform(buf1, key, iv)
	defer native.Wipe(iv1)
	if err != nil {
		return err
	}
	if !bytes.Equal(buf1, buf[:96]) {
		return fmt.Errorf("brngCTRRandInto stream mismatch")
	}
	if !bytes.Equal(iv1, gotIV) {
		return fmt.Errorf("brngCTRRandInto IV mismatch")
	}
	return nil
}

func mustDecodeHex(s string) []byte {
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		panic(err)
	}
	return b
}

func expectHex(name string, got []byte, wantHex string) error {
	want := mustDecodeHex(wantHex)
	defer native.Wipe(want)
	if !bytes.Equal(got, want) {
		return fmt.Errorf("%s mismatch", name)
	}
	return nil
}
