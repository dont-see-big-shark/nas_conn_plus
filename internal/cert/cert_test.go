package cert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func generateTestCert(t *testing.T, host string, serial int64, certPath, keyPath string) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{host},
	}

	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}

	crtOut, err := os.Create(certPath)
	if err != nil {
		t.Fatalf("create cert file: %v", err)
	}
	_ = pem.Encode(crtOut, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	crtOut.Close()

	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyOut, err := os.Create(keyPath)
	if err != nil {
		t.Fatalf("create key file: %v", err)
	}
	_ = pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})
	keyOut.Close()
}

func TestCertManager_SelfSigned(t *testing.T) {
	tempDir := t.TempDir()

	cm := NewManager("", "test.example.com", tempDir, true, false, "", "", "")
	if err := cm.Refresh(); err != nil {
		t.Fatalf("expected Refresh to succeed with self-signed, got: %v", err)
	}

	cur := cm.Current()
	if cur == nil {
		t.Fatal("expected loaded certificate to be non-nil")
	}

	crtPath := filepath.Join(tempDir, "selfsigned.crt")
	keyPath := filepath.Join(tempDir, "selfsigned.key")

	if _, err := os.Stat(crtPath); err != nil {
		t.Errorf("expected selfsigned.crt to exist, got: %v", err)
	}
	if _, err := os.Stat(keyPath); err != nil {
		t.Errorf("expected selfsigned.key to exist, got: %v", err)
	}

	// Second refresh should load the existing cert without errors
	if err := cm.Refresh(); err != nil {
		t.Fatalf("expected second Refresh to reload existing cert, got: %v", err)
	}
}

func TestCertManager_InPlaceReload(t *testing.T) {
	tempDir := t.TempDir()

	certFile := filepath.Join(tempDir, "app.crt")
	keyFile := filepath.Join(tempDir, "app.key")
	cfgFile := filepath.Join(tempDir, "certs.json")

	// 1. Initial certificate with serial 1001
	generateTestCert(t, "nas.home.local", 1001, certFile, keyFile)

	entries := []CertEntry{
		{Host: "nas.home.local", Cert: certFile, Key: keyFile},
	}
	cfgBytes, _ := json.Marshal(entries)
	if err := os.WriteFile(cfgFile, cfgBytes, 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cm := NewManager(cfgFile, "nas.home.local", tempDir, false, false, "", "", "")
	if err := cm.Refresh(); err != nil {
		t.Fatalf("initial refresh failed: %v", err)
	}

	cert1 := cm.Current()
	if cert1 == nil || len(cert1.Certificate) == 0 {
		t.Fatal("expected loaded certificate")
	}
	x509Cert1, _ := x509.ParseCertificate(cert1.Certificate[0])
	if x509Cert1.SerialNumber.Int64() != 1001 {
		t.Fatalf("expected serial 1001, got %d", x509Cert1.SerialNumber.Int64())
	}

	// 2. In-place overwrite certificate and key file (simulating certbot / acme.sh renewal)
	// Same exact file path!
	time.Sleep(10 * time.Millisecond)
	generateTestCert(t, "nas.home.local", 2002, certFile, keyFile)

	// Trigger Refresh
	if err := cm.Refresh(); err != nil {
		t.Fatalf("second refresh failed: %v", err)
	}

	cert2 := cm.Current()
	if cert2 == nil || len(cert2.Certificate) == 0 {
		t.Fatal("expected reloaded certificate")
	}
	x509Cert2, _ := x509.ParseCertificate(cert2.Certificate[0])
	if x509Cert2.SerialNumber.Int64() != 2002 {
		t.Errorf("In-place renewal failed! Expected serial 2002, still got %d (P1-1 regression)", x509Cert2.SerialNumber.Int64())
	}
}

func TestCertManager_ResolveCertFiles_Precedence(t *testing.T) {
	tempDir := t.TempDir()

	certExact := filepath.Join(tempDir, "exact.crt")
	keyExact := filepath.Join(tempDir, "exact.key")
	certFallback := filepath.Join(tempDir, "fallback.crt")
	keyFallback := filepath.Join(tempDir, "fallback.key")
	certWild := filepath.Join(tempDir, "wild.crt")
	keyWild := filepath.Join(tempDir, "wild.key")
	cfgFile := filepath.Join(tempDir, "certs.json")

	generateTestCert(t, "exact.local", 1, certExact, keyExact)
	generateTestCert(t, "fallback", 2, certFallback, keyFallback)
	generateTestCert(t, "*", 3, certWild, keyWild)

	// Order entries with wildcard first to verify it doesn't mistakenly match everything
	entries := []CertEntry{
		{Host: "*", Cert: certWild, Key: keyWild},
		{Host: "fallback", Cert: certFallback, Key: keyFallback},
		{Host: "exact.local", Cert: certExact, Key: keyExact},
	}
	cfgBytes, _ := json.Marshal(entries)
	_ = os.WriteFile(cfgFile, cfgBytes, 0o644)

	// 1. Asking for exact.local should return exact.crt (NOT wild.crt!)
	cmExact := NewManager(cfgFile, "exact.local", tempDir, false, false, "", "", "")
	c, k, err := cmExact.resolveCertFilesWith(cmExact.cfgPath, cmExact.host)
	if err != nil || c != certExact || k != keyExact {
		t.Errorf("expected exact.crt, got cert=%s, err=%v (M-a regression)", c, err)
	}

	// 2. Asking for unknown host should fallback to "fallback"
	cmUnknown := NewManager(cfgFile, "unknown.local", tempDir, false, false, "", "", "")
	c, k, err = cmUnknown.resolveCertFilesWith(cmUnknown.cfgPath, cmUnknown.host)
	if err != nil || c != certFallback || k != keyFallback {
		t.Errorf("expected fallback.crt for unknown host, got cert=%s, err=%v", c, err)
	}
}

func TestCertManager_GetCertificate(t *testing.T) {
	tempDir := t.TempDir()

	// 1. Uninitialized cert manager -> returns error
	cmEmpty := NewManager("", "nas.local", tempDir, false, false, "", "", "")
	_, err := cmEmpty.GetCertificate(&tls.ClientHelloInfo{ServerName: "nas.local"})
	if err == nil {
		t.Error("expected error when no cert is loaded")
	}

	// 2. Initialized cert manager -> returns loaded cert
	cmValid := NewManager("", "nas.local", tempDir, true, false, "", "", "")
	if err := cmValid.Refresh(); err != nil {
		t.Fatalf("refresh: %v", err)
	}

	cert, err := cmValid.GetCertificate(&tls.ClientHelloInfo{ServerName: "nas.local"})
	if err != nil {
		t.Fatalf("GetCertificate failed: %v", err)
	}
	if cert == nil {
		t.Fatal("expected non-nil cert")
	}
}

func TestCertManager_ResolveCertFiles_Errors(t *testing.T) {
	tempDir := t.TempDir()

	// 1. Missing config file
	cmMissing := NewManager(filepath.Join(tempDir, "nonexistent.json"), "nas.local", tempDir, false, false, "", "", "")
	if _, _, err := cmMissing.resolveCertFilesWith(cmMissing.cfgPath, cmMissing.host); err == nil {
		t.Error("expected error for nonexistent cert config file")
	}

	// 2. Malformed json
	malformedCfg := filepath.Join(tempDir, "malformed.json")
	_ = os.WriteFile(malformedCfg, []byte("bad json"), 0o644)
	cmMalformed := NewManager(malformedCfg, "nas.local", tempDir, false, false, "", "", "")
	if _, _, err := cmMalformed.resolveCertFilesWith(cmMalformed.cfgPath, cmMalformed.host); err == nil {
		t.Error("expected error for malformed json")
	}

	// 3. No match and no fallback
	noMatchCfg := filepath.Join(tempDir, "nomatch.json")
	entries := []CertEntry{
		{Host: "other.domain.com", Cert: "/tmp/a.crt", Key: "/tmp/a.key"},
	}
	b, _ := json.Marshal(entries)
	_ = os.WriteFile(noMatchCfg, b, 0o644)
	cmNoMatch := NewManager(noMatchCfg, "nas.local", tempDir, false, false, "", "", "")
	if _, _, err := cmNoMatch.resolveCertFilesWith(cmNoMatch.cfgPath, cmNoMatch.host); err == nil {
		t.Error("expected error when no host matches and no fallback")
	}
}
