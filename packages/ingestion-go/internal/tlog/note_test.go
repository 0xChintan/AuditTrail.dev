package tlog

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"golang.org/x/mod/sumdb/note"
)

func TestLogSignatureInteropsWithXModNote(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	s := Signer{Name: "audittrail.dev/log/test", Priv: priv}
	cp := Checkpoint{Origin: s.Name, Size: 42, Root: make([]byte, 32)}
	signed := SignCheckpoint(cp, s)

	v, err := note.NewVerifier(s.Vkey())
	if err != nil {
		t.Fatalf("x/mod rejects our vkey: %v", err)
	}
	n, err := note.Open(signed, note.VerifierList(v))
	if err != nil {
		t.Fatalf("x/mod rejects our signed note: %v", err)
	}
	if n.Text != cp.Text() {
		t.Fatal("text mismatch")
	}
	// ...and the reverse: x/mod-signed notes verify with our code.
	skey, vkey, _ := note.GenerateKey(rand.Reader, "example.com/other")
	xs, _ := note.NewSigner(skey)
	msg, _ := note.Sign(&note.Note{Text: cp.Text()}, xs)
	name, typ, pub, err := ParseVkey(vkey)
	if err != nil || typ != TypeEd25519 {
		t.Fatalf("parse x/mod vkey: %v", err)
	}
	pn, err := ParseNote(msg)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyLog(pn, name, pub); err != nil {
		t.Fatal(err)
	}
}

func TestCosignatureRoundTripAndTamper(t *testing.T) {
	_, lp, _ := ed25519.GenerateKey(rand.Reader)
	_, wp, _ := ed25519.GenerateKey(rand.Reader)
	s := Signer{Name: "audittrail.dev/log/x", Priv: lp}
	w := Cosigner{Name: "witness.example/w1", Priv: wp}
	cp := Checkpoint{Origin: s.Name, Size: 7, Root: make([]byte, 32)}
	signed := string(SignCheckpoint(cp, s)) + w.CosignLine(cp.Text(), time.Unix(1790000000, 0))
	n, err := ParseNote([]byte(signed))
	if err != nil {
		t.Fatal(err)
	}
	wit, _ := WitnessFromVkey(w.Vkey())
	at, ok, err := VerifyCosig(n, wit)
	if err != nil || !ok || at.Unix() != 1790000000 {
		t.Fatalf("cosig: %v %v %v", at, ok, err)
	}
	tampered := strings.Replace(signed, "\n7\n", "\n8\n", 1)
	n2, _ := ParseNote([]byte(tampered))
	if _, _, err := VerifyCosig(n2, wit); err == nil {
		t.Fatal("cosignature verified over tampered checkpoint")
	}
	if err := VerifyLog(n2, s.Name, s.Pub()); err == nil {
		t.Fatal("log signature verified over tampered checkpoint")
	}
}
