// Package examples contains small, compile-checked public API examples.
package examples_test

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log"

	bee2 "github.com/miniusercoder/bee2go/v3"
	"github.com/miniusercoder/bee2go/v3/bake"
	"github.com/miniusercoder/bee2go/v3/bash"
	"github.com/miniusercoder/bee2go/v3/bels"
	"github.com/miniusercoder/bee2go/v3/belt"
	"github.com/miniusercoder/bee2go/v3/bign"
	"github.com/miniusercoder/bee2go/v3/botp"
	"github.com/miniusercoder/bee2go/v3/bpki"
	"github.com/miniusercoder/bee2go/v3/brng"
	"github.com/miniusercoder/bee2go/v3/btok"
	"github.com/miniusercoder/bee2go/v3/dstu"
	"github.com/miniusercoder/bee2go/v3/g12s"
	"github.com/miniusercoder/bee2go/v3/pfok"
	"github.com/miniusercoder/bee2go/v3/rng"
	"github.com/miniusercoder/bee2go/v3/selftest"
	"github.com/miniusercoder/bee2go/v3/stb99"
)

func Example_belt() {
	h, err := belt.NewHash()
	if err != nil {
		log.Fatal(err)
	}
	defer h.Close()
	if _, err = h.Write([]byte("hello")); err != nil {
		log.Fatal(err)
	}
	fmt.Println(len(h.Sum(nil)))
	// Output: 32
}
func Example_bash() {
	digest, err := bash.Hash(128, []byte("hello"))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(len(digest))
	// Output: 32
}
func Example_bign() {
	digest, err := belt.Hash([]byte("message"))
	if err != nil {
		log.Fatal(err)
	}
	priv, pub, err := bign.Profile128.GenerateKey(nil)
	if err != nil {
		log.Fatal(err)
	}
	sig, err := bign.Profile128.SignDigestDeterministic(digest, priv, nil)
	if err != nil {
		log.Fatal(err)
	}
	if err = bign.Profile128.VerifyDigest(digest, sig, pub); err != nil {
		log.Fatal(err)
	}
	fmt.Println("verified")
	// Output: verified
}
func Example_bake() {
	// In an application, source the secret and IV from the protocol.
	secret, iv := make([]byte, 32), make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, secret); err != nil {
		log.Fatal(err)
	}
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		log.Fatal(err)
	}
	derived, err := bake.KDF(secret, iv, 1)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(len(derived))
	// Output: 32
}
func Example_bels() {
	secret := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, secret); err != nil {
		log.Fatal(err)
	}
	shares, err := bels.ShareStandard(secret, 3, 2, nil)
	if err != nil {
		log.Fatal(err)
	}
	recovered, err := bels.RecoverStandard(shares[:2], 2)
	if err != nil {
		log.Fatal(err)
	}
	// Share recovery does not authenticate the result.
	fmt.Println(len(recovered))
	// Output: 32
}
func Example_botp() {
	// Use a provisioned secret and the protocol's agreed counter.
	key := []byte("example-key-replace-before-use")
	code, err := botp.HOTPCode(key, 6, [8]byte{})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(len(code))
	// Output: 6
}
func Example_bpki() {
	key, salt := make([]byte, 32), make([]byte, 8)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		log.Fatal(err)
	}
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		log.Fatal(err)
	}
	// Obtain the password from the user or a secrets manager in a real application.
	protection := bpki.Protection{Password: []byte("example-only"), Salt: salt, Iterations: 10000}
	der, err := bpki.WrapPrivateKey(key, protection)
	if err != nil {
		log.Fatal(err)
	}
	recovered, err := bpki.UnwrapPrivateKey(der, protection.Password)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(len(recovered))
	// Output: 32
}
func Example_brng() {
	key, iv := make([]byte, 32), make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		log.Fatal(err)
	}
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		log.Fatal(err)
	}
	g, err := brng.NewCTR(key, iv)
	if err != nil {
		log.Fatal(err)
	}
	defer g.Close()
	out := make([]byte, 32)
	if _, err = io.ReadFull(g, out); err != nil {
		log.Fatal(err)
	}
	fmt.Println(len(out))
	// Output: 32
}
func Example_btok() {
	state := btok.PasswordState{PIN: btok.PINOperational, Auth: btok.AuthNone}
	allowed, err := state.Transition(btok.PINSuccess)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(allowed)
	// Output: true
}
func Example_dstu() {
	p, err := dstu.Standard("1.2.804.2.1.1.1.1.3.1.1.1.2.0")
	if err != nil {
		log.Fatal(err)
	}
	defer p.Close()
	if err = p.Validate(); err != nil {
		log.Fatal(err)
	}
	fmt.Println("parameters valid")
	// Output: parameters valid
}
func Example_g12s() {
	p, err := g12s.Standard("1.2.643.2.2.35.1")
	if err != nil {
		log.Fatal(err)
	}
	defer p.Close()
	if err = p.Validate(); err != nil {
		log.Fatal(err)
	}
	fmt.Println("parameters valid")
	// Output: parameters valid
}
func Example_pfok() {
	p, seed, err := pfok.Standard("1.2.112.0.2.0.1176.2.3.3.2")
	if err != nil {
		log.Fatal(err)
	}
	if err = seed.Validate(); err != nil {
		log.Fatal(err)
	}
	if err = p.Validate(); err != nil {
		log.Fatal(err)
	}
	fmt.Println("parameters valid")
	// Output: parameters valid
}
func Example_stb99() {
	p, seed, err := stb99.Standard("1.2.112.0.2.0.1176.2.3.3.1")
	if err != nil {
		log.Fatal(err)
	}
	if err = seed.Validate(); err != nil {
		log.Fatal(err)
	}
	if err = p.Validate(); err != nil {
		log.Fatal(err)
	}
	fmt.Println("parameters valid")
	// Output: parameters valid
}
func Example_rng() {
	g, err := rng.New()
	if err != nil {
		log.Fatal(err)
	}
	defer g.Close()
	b := make([]byte, 32)
	if _, err = io.ReadFull(g, b); err != nil {
		log.Fatal(err)
	}
	fmt.Println(len(b))
	// Output: 32
}
func Example_selftest() {
	for _, result := range selftest.Run() {
		if result.Err != nil {
			log.Fatal(result.Err)
		}
	}
	fmt.Println("diagnostics passed")
	// Output: diagnostics passed
}

func Example_errors() {
	_, err := belt.NewBlock([]byte("short"))
	fmt.Println(errors.Is(err, bee2.ErrInvalidInput))
	// Output: true
}
