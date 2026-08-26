package sites

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

// selfSignedPEM generates a throwaway self-signed cert (real x509 bytes,
// not a fixture) expiring at notAfter, so parseCertStatus can be tested
// against actual crypto/x509 parsing without touching the filesystem or
// needing certbot installed.
func selfSignedPEM(t *testing.T, notAfter time.Time) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestParseCertStatus_ValidCert(t *testing.T) {
	pemBytes := selfSignedPEM(t, time.Now().Add(60*24*time.Hour))
	st := parseCertStatus(pemBytes)
	if !st.Exists {
		t.Fatalf("expected Exists=true, error: %s", st.Error)
	}
	if st.DaysLeft < 58 || st.DaysLeft > 60 {
		t.Errorf("expected ~60 days left, got %d", st.DaysLeft)
	}
}

func TestParseCertStatus_ExpiredCert(t *testing.T) {
	pemBytes := selfSignedPEM(t, time.Now().Add(-24*time.Hour))
	st := parseCertStatus(pemBytes)
	if !st.Exists {
		t.Fatalf("expected Exists=true (parseable, just expired), error: %s", st.Error)
	}
	if st.DaysLeft >= 0 {
		t.Errorf("expected negative DaysLeft for an expired cert, got %d", st.DaysLeft)
	}
}

func TestParseCertStatus_GarbageInput(t *testing.T) {
	st := parseCertStatus([]byte("not a certificate"))
	if st.Exists {
		t.Error("expected Exists=false for unparseable input")
	}
	if st.Error == "" {
		t.Error("expected a non-empty Error message")
	}
}
