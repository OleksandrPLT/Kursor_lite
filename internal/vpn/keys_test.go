package vpn

import (
	"encoding/base64"
	"testing"
)

func TestGeneratePrivateKeyIsClamped(t *testing.T) {
	priv, err := GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(priv)
	if err != nil {
		t.Fatalf("private key isn't valid base64: %v", err)
	}
	if len(raw) != 32 {
		t.Fatalf("private key is %d bytes, want 32", len(raw))
	}
	if raw[0]&7 != 0 {
		t.Error("low 3 bits of first byte should be cleared (Curve25519 clamping)")
	}
	if raw[31]&128 != 0 {
		t.Error("high bit of last byte should be cleared (Curve25519 clamping)")
	}
	if raw[31]&64 == 0 {
		t.Error("second-highest bit of last byte should be set (Curve25519 clamping)")
	}
}

func TestGeneratePrivateKeyIsRandom(t *testing.T) {
	a, err := GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	b, err := GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("two calls produced the same key")
	}
}

func TestPublicKeyIsDeterministicAndDistinct(t *testing.T) {
	priv, err := GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	pub1, err := PublicKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	pub2, err := PublicKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	if pub1 != pub2 {
		t.Fatal("PublicKey isn't deterministic for the same private key")
	}
	if pub1 == priv {
		t.Fatal("public key equals private key — something is very wrong")
	}

	other, _ := GeneratePrivateKey()
	otherPub, err := PublicKey(other)
	if err != nil {
		t.Fatal(err)
	}
	if otherPub == pub1 {
		t.Fatal("two different private keys produced the same public key")
	}
}

func TestPublicKeyRejectsGarbage(t *testing.T) {
	if _, err := PublicKey("not-base64!!!"); err == nil {
		t.Fatal("expected an error for invalid base64")
	}
	if _, err := PublicKey(base64.StdEncoding.EncodeToString([]byte("too short"))); err == nil {
		t.Fatal("expected an error for a key that isn't 32 bytes")
	}
}
