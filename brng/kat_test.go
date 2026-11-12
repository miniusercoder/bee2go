package brng

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func decode(s string) []byte {
	b, e := hex.DecodeString(s)
	if e != nil {
		panic(e)
	}
	return b
}
func TestUpstreamHMAC(t *testing.T) {
	h := beltHBytes()
	r, e := NewHMAC(h[128:160], h[192:224])
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	out := make([]byte, 96)
	r.Read(out[:32])
	r.Read(out[32:43])
	r.Read(out[43:62])
	r.Read(out[62:64])
	r.Read(out[64:])
	if !bytes.Equal(out, decode("AF907A0E470A3A1B268ECCCCC0B90F239FE94A2DC6E014179FC789CB3C3887E4695C6B96B84948F8D76924E22260859DB9B5FE757BEDA2E17103EE44655A9FEF648077CCC5002E0561C6EF512C513B8C24B4F3A157221CFBC1597E969778C1E4")) {
		t.Fatal("upstream HMAC B.4 mismatch")
	}
	one, e := HMACRand(96, h[128:160], h[192:224])
	if e != nil || !bytes.Equal(one, out) {
		t.Fatal(e)
	}
	short, e := HMACRand(2, h[128:129], h[192:193])
	if e != nil || !bytes.Equal(short, decode("42B1")) {
		t.Fatal(e)
	}
}
func TestUpstreamCTRTransformAndIV(t *testing.T) {
	h := beltHBytes()
	r, e := NewCTR(h[128:160], h[192:224])
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	out := append([]byte(nil), h...)
	r.Transform(out[:32])
	r.Transform(out[32:64])
	r.Transform(out[64:96])
	iv, e := r.IV()
	if e != nil || !bytes.Equal(iv, decode("C132971343FC9A48A02A885F194B09A17ECDA4D01544AF8CA58450BF66D2E88A")) {
		t.Fatal(e)
	}
	r.Transform(out[96:])
	if !bytes.Equal(out, decode("1F66B5B84B7339674533F0329C74F21834281FED0732429E0C79235FC273E2694C0E74B2CD5811AD21F23DE7E0FA742C3ED6EC483C461CE15C33A77AA308B7D20F51D91347617C20BD4AB07AEF4F26A1AD1362A8F9A3D42FBE1B8E6F1C88AAD50A4E8298BE0839E46F19409F637F4415572251DD0D39284F0F0390D93BBCE9ECF81B29D571F6452FF8B2B97F57E18A58BC946FEE45EAB32B06FCAC23A33F422BC431B41BBE8E802288737ACF45A29251FC736A3C6F478F77A7ED271D5EEDAA58E98309303623AFD33017C42BC6D43C15438446EE57D46E412EFC0B61B5FBA39ED37BABE50BFEEB8ED162BB1393D46FB43534A201EB3B1A5C085DC5068ED6F89A")) {
		t.Fatal("upstream CTR B.2 mismatch")
	}
	buf := append([]byte(nil), h[:96]...)
	iv, e = CTRTransform(buf, h[128:160], h[192:224])
	if e != nil || !bytes.Equal(buf, out[:96]) || !bytes.Equal(iv, decode("C132971343FC9A48A02A885F194B09A17ECDA4D01544AF8CA58450BF66D2E88A")) {
		t.Fatal(e)
	}
}
func TestRandBoundaries(t *testing.T) {
	if b, _, e := CTRRand(-1, make([]byte, 32), nil); b != nil || e == nil {
		t.Fatal("negative count")
	}
	if b, e := HMACRand(-1, nil, nil); b != nil || e == nil {
		t.Fatal("negative count")
	}
	r, e := NewHMAC(nil, nil)
	if e != nil {
		t.Fatal(e)
	}
	r.Close()
	if _, e = r.Read(nil); e == nil {
		t.Fatal("closed HMAC")
	}
	if b, _, e := CTRRand(0, make([]byte, 32), nil); e != nil || len(b) != 0 {
		t.Fatal(e)
	}
}
