package integration

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/miniusercoder/bee2go/v3/bake"
	"github.com/miniusercoder/bee2go/v3/bign"
)

type frameTransport struct {
	r io.Reader
	w io.Writer
}

func (t frameTransport) Send(b []byte) error {
	if len(b) > 65536 {
		return errors.New("frame too large")
	}
	var h [4]byte
	binary.BigEndian.PutUint32(h[:], uint32(len(b)))
	if _, e := t.w.Write(h[:]); e != nil {
		return e
	}
	_, e := t.w.Write(b)
	return e
}
func (t frameTransport) Receive() ([]byte, error) {
	var h [4]byte
	if _, e := io.ReadFull(t.r, h[:]); e != nil {
		return nil, e
	}
	n := binary.BigEndian.Uint32(h[:])
	if n > 65536 {
		return nil, errors.New("frame too large")
	}
	b := make([]byte, n)
	_, e := io.ReadFull(t.r, b)
	return b, e
}
func peerBinary(t *testing.T) string {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "../.."))
	out := filepath.Join(t.TempDir(), "bake-peer")
	cmd := exec.Command("cc", "-std=c11", "-I"+filepath.Join(root, "bee2/include"), filepath.Join(root, "tests/integration/testdata/bake_peer.c"), filepath.Join(root, "build/bee2/src/libbee2_static.a"), "-lpthread", "-o", out)
	if os.Getenv("BEE2_TEST_SANITIZERS") == "1" {
		cmd.Args = append(cmd.Args, "-fsanitize=address,undefined", "-fno-sanitize=signed-integer-overflow")
	}
	if b, e := cmd.CombinedOutput(); e != nil {
		t.Fatalf("compile C peer: %v\n%s", e, b)
	}
	return out
}
func validator(expected []byte) bake.CertValidator {
	return func(_ []byte, cert []byte) ([]byte, error) {
		if !bytes.Equal(cert, expected) {
			return nil, errors.New("unexpected certificate")
		}
		return append([]byte(nil), cert...), nil
	}
}
func TestBakeGoCInterop(t *testing.T) {
	bin := peerBinary(t)
	p, e := bign.StandardParams(bign.Curve256v1)
	if e != nil {
		t.Fatal(e)
	}
	defer p.Close()
	privA, privB := make([]byte, 32), make([]byte, 32)
	privA[0] = 1
	privB[0] = 2
	pubA, e := bign.PublicKey(p, privA)
	if e != nil {
		t.Fatal(e)
	}
	pubB, e := bign.PublicKey(p, privB)
	if e != nil {
		t.Fatal(e)
	}
	for _, kind := range []string{"bmqv", "bsts", "bpace"} {
		for _, role := range []bake.Role{bake.RoleA, bake.RoleB} {
			for flags := 0; flags < 4; flags++ {
				if kind == "bsts" && flags != 3 {
					continue
				}
				name := fmt.Sprintf("%s/GoRole%d/flags%d", kind, role, flags)
				t.Run(name, func(t *testing.T) {
					ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
					defer cancel()
					peerRole := "A"
					priv, local, remote := privB, pubB, pubA
					if role == bake.RoleA {
						peerRole = "B"
						priv, local, remote = privA, pubA, pubB
					}
					cmd := exec.CommandContext(ctx, bin, kind, peerRole, fmt.Sprint(flags))
					var stderr bytes.Buffer
					cmd.Stderr = &stderr
					stdin, e := cmd.StdinPipe()
					if e != nil {
						t.Fatal(e)
					}
					stdout, e := cmd.StdoutPipe()
					if e != nil {
						t.Fatal(e)
					}
					if e = cmd.Start(); e != nil {
						t.Fatal(e)
					}
					defer func() {
						stdin.Close()
						if cmd.ProcessState == nil {
							cmd.Process.Kill()
							cmd.Wait()
						}
					}()
					tr := frameTransport{stdout, stdin}
					settings := bake.Settings{ConfirmA: flags&1 != 0, ConfirmB: flags&2 != 0}
					var key []byte
					switch kind {
					case "bmqv":
						s, e := bake.NewBMQV(p, role, settings, priv, bake.Certificate{Data: local, Validate: validator(local)})
						if e != nil {
							t.Fatal(e)
						}
						defer s.Close()
						key, e = s.Run(tr, bake.Certificate{Data: remote, Validate: validator(remote)})
					case "bsts":
						s, e := bake.NewBSTS(p, role, settings, priv, bake.Certificate{Data: local, Validate: validator(local)})
						if e != nil {
							t.Fatal(e)
						}
						defer s.Close()
						key, e = s.Run(tr, validator(remote))
					case "bpace":
						s, e := bake.NewBPACE(p, role, settings, []byte("password"))
						if e != nil {
							t.Fatal(e)
						}
						defer s.Close()
						key, e = s.Run(tr)
					}
					if e != nil {
						stdin.Close()
						cmd.Process.Kill()
						cmd.Wait()
						t.Fatalf("Go runner: %v; C stderr: %s", e, stderr.String())
					}
					other, e := tr.Receive()
					if e != nil {
						stdin.Close()
						cmd.Process.Kill()
						cmd.Wait()
						t.Fatalf("read C key: %v; stderr: %s", e, stderr.String())
					}
					if e = cmd.Wait(); e != nil {
						t.Fatalf("C peer: %v; stderr: %s", e, stderr.String())
					}
					if len(key) != 32 || !bytes.Equal(key, other) {
						t.Fatalf("key mismatch Go=%x C=%x", key, other)
					}
				})
			}
		}
	}
}
