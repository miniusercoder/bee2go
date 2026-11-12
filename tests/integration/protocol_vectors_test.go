package integration

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/miniusercoder/bee2go/v3/bake"
	"github.com/miniusercoder/bee2go/v3/bign"
	"github.com/miniusercoder/bee2go/v3/btok"
	"os"
	"strconv"
	"strings"
	"testing"
)

type protocolVector struct {
	kind, level, flags int
	messages           [4][]byte
	key                []byte
}

func protocolVectors(t *testing.T) []protocolVector {
	t.Helper()
	f, e := os.Open("testdata/protocol_vectors.txt")
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	var out []protocolVector
	s := bufio.NewScanner(f)
	for s.Scan() {
		cols := strings.Fields(s.Text())
		if len(cols) != 8 {
			t.Fatal("invalid fixture row")
		}
		v := protocolVector{}
		v.kind, _ = strconv.Atoi(cols[0])
		v.level, _ = strconv.Atoi(cols[1])
		v.flags, _ = strconv.Atoi(cols[2])
		for i := 0; i < 5; i++ {
			var b []byte
			if cols[i+3] != "-" {
				b, e = hex.DecodeString(cols[i+3])
				if e != nil {
					t.Fatal(e)
				}
			}
			if i < 4 {
				v.messages[i] = b
			} else {
				v.key = b
			}
		}
		out = append(out, v)
	}
	if e = s.Err(); e != nil {
		t.Fatal(e)
	}
	if len(out) != 15 {
		t.Fatalf("fixture count %d", len(out))
	}
	return out
}
func replayProtocol(v protocolVector, tamper int) (messages [4][]byte, aKey, bKey []byte, err error) {
	oid := fmt.Sprintf("1.2.112.0.2.0.34.101.45.3.%d", v.level/64-1)
	p, e := bign.StandardParams(oid)
	if e != nil {
		return messages, nil, nil, e
	}
	defer p.Close()
	a, b := make([]byte, v.level/4), make([]byte, v.level/4)
	a[0] = 1
	b[0] = 2
	A, e := bign.PublicKey(p, a)
	if e != nil {
		return messages, nil, nil, e
	}
	B, e := bign.PublicKey(p, b)
	if e != nil {
		return messages, nil, nil, e
	}
	ca := bake.Certificate{Data: A, Validate: validator(A)}
	cb := bake.Certificate{Data: B, Validate: validator(B)}
	seedA, seedB := make([]byte, 64), make([]byte, 64)
	seedA[0] = 1
	seedB[0] = 2
	sa := bake.Settings{ConfirmA: v.flags&1 != 0, ConfirmB: v.flags&2 != 0, Entropy: bytes.NewReader(seedA)}
	sb := sa
	sb.Entropy = bytes.NewReader(seedB)
	wire := func(i int, b []byte) []byte {
		out := append([]byte(nil), b...)
		if tamper == i && len(out) > 0 {
			out[len(out)-1] ^= 1
		}
		return out
	}
	switch v.kind {
	case 1:
		x, e := bake.NewBMQV(p, bake.RoleA, sa, a, ca)
		if e != nil {
			return messages, nil, nil, e
		}
		defer x.Close()
		y, e := bake.NewBMQV(p, bake.RoleB, sb, b, cb)
		if e != nil {
			return messages, nil, nil, e
		}
		defer y.Close()
		messages[0], err = y.Step2()
		if err != nil {
			return
		}
		messages[1], err = x.Step3(wire(0, messages[0]), cb)
		if err != nil {
			return
		}
		messages[2], err = y.Step4(wire(1, messages[1]), ca)
		if err != nil {
			return
		}
		if sb.ConfirmB {
			err = x.Step5(wire(2, messages[2]))
			if err != nil {
				return
			}
		}
		aKey, err = x.Key()
		if err == nil {
			bKey, err = y.Key()
		}
	case 2:
		x, e := bake.NewBSTS(p, bake.RoleA, sa, a, ca)
		if e != nil {
			return messages, nil, nil, e
		}
		defer x.Close()
		y, e := bake.NewBSTS(p, bake.RoleB, sb, b, cb)
		if e != nil {
			return messages, nil, nil, e
		}
		defer y.Close()
		messages[0], err = y.Step2()
		if err != nil {
			return
		}
		messages[1], err = x.Step3(wire(0, messages[0]))
		if err != nil {
			return
		}
		messages[2], err = y.Step4(wire(1, messages[1]), ca.Validate)
		if err != nil {
			return
		}
		err = x.Step5(wire(2, messages[2]), cb.Validate)
		if err != nil {
			return
		}
		aKey, err = x.Key()
		if err == nil {
			bKey, err = y.Key()
		}
	case 3:
		x, e := bake.NewBPACE(p, bake.RoleA, sa, []byte("password"))
		if e != nil {
			return messages, nil, nil, e
		}
		defer x.Close()
		y, e := bake.NewBPACE(p, bake.RoleB, sb, []byte("password"))
		if e != nil {
			return messages, nil, nil, e
		}
		defer y.Close()
		messages[0], err = y.Step2()
		if err != nil {
			return
		}
		messages[1], err = x.Step3(wire(0, messages[0]))
		if err != nil {
			return
		}
		messages[2], err = y.Step4(wire(1, messages[1]))
		if err != nil {
			return
		}
		messages[3], err = x.Step5(wire(2, messages[2]))
		if err != nil {
			return
		}
		if sa.ConfirmA {
			err = y.Step6(wire(3, messages[3]))
			if err != nil {
				return
			}
		}
		aKey, err = x.Key()
		if err == nil {
			bKey, err = y.Key()
		}
	case 4:
		x, e := btok.NewBAuthTerminal(p, sa, a, ca)
		if e != nil {
			return messages, nil, nil, e
		}
		defer x.Close()
		y, e := btok.NewBAuthToken(p, sb, b, cb)
		if e != nil {
			return messages, nil, nil, e
		}
		defer y.Close()
		messages[0], err = y.Step2(ca)
		if err != nil {
			return
		}
		messages[1], err = x.Step3(wire(0, messages[0]))
		if err != nil {
			return
		}
		messages[2], err = y.Step4(wire(1, messages[1]))
		if err != nil {
			return
		}
		if sa.ConfirmB {
			err = x.Step5(wire(2, messages[2]), cb.Validate)
			if err != nil {
				return
			}
		}
		aKey, err = x.Key()
		if err == nil {
			bKey, err = y.Key()
		}
	default:
		err = fmt.Errorf("invalid fixture protocol")
	}
	return
}
func TestProtocolIndependentCTranscripts(t *testing.T) {
	for _, v := range protocolVectors(t) {
		t.Run(fmt.Sprintf("kind%d/level%d/flags%d", v.kind, v.level, v.flags), func(t *testing.T) {
			m, a, b, e := replayProtocol(v, -1)
			if e != nil {
				t.Fatal(e)
			}
			for i := range m {
				if !bytes.Equal(m[i], v.messages[i]) {
					t.Fatalf("M%d differs from independent C vector", i+1)
				}
			}
			if !bytes.Equal(a, v.key) || !bytes.Equal(b, v.key) {
				t.Fatal("key differs from independent C vector")
			}
		})
	}
}
func TestProtocolTamperEveryMessage(t *testing.T) {
	for _, v := range protocolVectors(t) {
		if v.flags != 3 {
			continue
		}
		for i, m := range v.messages {
			if len(m) == 0 {
				continue
			}
			t.Run(fmt.Sprintf("kind%d/level%d/M%d", v.kind, v.level, i+1), func(t *testing.T) {
				_, a, b, e := replayProtocol(v, i)
				if e == nil || a != nil || b != nil {
					t.Fatal("corrupted handshake released a key", e)
				}
			})
		}
	}
}
