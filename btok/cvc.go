package btok

import "github.com/miniusercoder/bee2go/v3/internal/native"

// Certificate is the typed content of a CV certificate; dates contain YYMMDD digits.
type Certificate struct {
	Authority, Holder string
	PublicKey         []byte
	From, Until       [6]byte
	EID               [5]byte
	ESign             [2]byte
	Signature         []byte
}

func CheckCertificate(c Certificate) error { return native.BTOKCVCCheck(native.CVCCertificate(c), nil) }
func CheckCertificateForIssuer(c, issuer Certificate) error {
	v := native.CVCCertificate(issuer)
	return native.BTOKCVCCheck(native.CVCCertificate(c), &v)
}
func WrapCertificate(c Certificate, key []byte) ([]byte, Certificate, error) {
	der, v, e := native.BTOKCVCWrap(native.CVCCertificate(c), key, nil, false)
	return der, Certificate(v), e
}
func IssueCertificate(c Certificate, issuer, key []byte) ([]byte, Certificate, error) {
	der, v, e := native.BTOKCVCWrap(native.CVCCertificate(c), key, issuer, true)
	return der, Certificate(v), e
}

// UnwrapCertificate verifies the signature if pubkey is supplied; nil only parses the certificate.
func UnwrapCertificate(cert, pubkey []byte) (Certificate, error) {
	v, e := native.BTOKCVCUnwrap(cert, pubkey)
	return Certificate(v), e
}
func CertificateLength(der []byte) (int, error) { return native.BTOKCVCLength(der) }
func ValidateCertificate(cert, issuer []byte, date *[6]byte) error {
	return native.BTOKCVCValidate(cert, issuer, date)
}
func ValidateCertificateForIssuer(cert []byte, issuer Certificate, date *[6]byte) (Certificate, error) {
	v, e := native.BTOKCVCValidate2(cert, native.CVCCertificate(issuer), date)
	return Certificate(v), e
}
func MatchCertificate(cert, key []byte) error { return native.BTOKCVCMatch(cert, key) }
