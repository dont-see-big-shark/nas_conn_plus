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
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

type CertEntry struct {
	Host string `json:"host"`
	Cert string `json:"cert"`
	Key  string `json:"key"`
}

type Manager struct {
	cfgPath  string
	host     string
	selfDir  string
	fallback bool

	// ACME
	acmeEnabled bool
	acmeDomain  string
	acmeMgr     *autocert.Manager

	mu       sync.Mutex
	cur      *tls.Certificate
	loadedAt string
}

// NewManager creates a new TLS certificate manager with optional ACME support
func NewManager(cfgPath, host, selfDir string, fallback bool, acmeEnabled bool, acmeDomain, acmeEmail, acmeCacheDir string) *Manager {
	mgr := &Manager{
		cfgPath:     cfgPath,
		host:        host,
		selfDir:     selfDir,
		fallback:    fallback,
		acmeEnabled: acmeEnabled,
		acmeDomain:  acmeDomain,
	}

	if acmeEnabled && acmeDomain != "" {
		_ = os.MkdirAll(acmeCacheDir, 0o700)
		mgr.acmeMgr = &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(acmeDomain),
			Cache:      autocert.DirCache(acmeCacheDir),
			Email:      acmeEmail,
		}
	}

	return mgr
}

// GetCertificate implements dynamic certificate resolution for tls.Config
func (m *Manager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	// 1. Try ACME if enabled and SNI matches
	if m.acmeEnabled && m.acmeMgr != nil {
		if hello.ServerName == m.acmeDomain || m.acmeDomain == "" {
			cert, err := m.acmeMgr.GetCertificate(hello)
			if err == nil && cert != nil {
				return cert, nil
			}
		}
	}

	// 2. Return currently loaded static or self-signed certificate
	m.mu.Lock()
	cur := m.cur
	m.mu.Unlock()

	if cur != nil {
		return cur, nil
	}

	return nil, fmt.Errorf("no certificate available for %q", hello.ServerName)
}

// Current returns the currently loaded certificate in a thread-safe manner
func (m *Manager) Current() *tls.Certificate {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cur
}

// Refresh reloads the certificate from disk or regenerates self-signed if needed
func (m *Manager) Refresh() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var lastErr error

	// Try loading from cert_config_path if provided
	if m.cfgPath != "" {
		certFile, keyFile, err := m.resolveCertFiles()
		if err == nil {
			kc, kerr := tls.LoadX509KeyPair(certFile, keyFile)
			if kerr == nil {
				fp := "file:" + certFile
				if fp != m.loadedAt {
					m.cur = &kc
					m.loadedAt = fp
				}
				return nil
			}
			lastErr = fmt.Errorf("load keypair from %s: %w", certFile, kerr)
		} else {
			lastErr = err
		}
	}

	// If ACME is enabled, we don't strictly require a static certificate
	if m.acmeEnabled && m.acmeMgr != nil {
		return nil
	}

	// Fallback to self-signed certificate if allowed
	if m.fallback {
		sc, err := m.loadOrCreateSelfSigned()
		if err == nil && sc != nil {
			fp := "self:" + m.host
			if fp != m.loadedAt {
				m.cur = sc
				m.loadedAt = fp
			}
			return nil
		}
		if err != nil {
			lastErr = fmt.Errorf("generate self-signed: %w", err)
		}
	}

	if lastErr == nil {
		lastErr = fmt.Errorf("no certificate source configured and self-signed fallback disabled")
	}
	return lastErr
}

func (m *Manager) resolveCertFiles() (string, string, error) {
	b, err := os.ReadFile(m.cfgPath)
	if err != nil {
		return "", "", err
	}

	// Try parsing as JSON array of cert entries
	var entries []CertEntry
	if err := json.Unmarshal(b, &entries); err == nil && len(entries) > 0 {
		for _, want := range []string{m.host, "fallback", "*"} {
			for _, e := range entries {
				if (e.Host == want || want == "*") && e.Cert != "" && e.Key != "" {
					return e.Cert, e.Key, nil
				}
			}
		}
		return "", "", fmt.Errorf("cert for host %q not found in %s", m.host, m.cfgPath)
	}

	return "", "", fmt.Errorf("invalid cert config format in %s", m.cfgPath)
}

func (m *Manager) loadOrCreateSelfSigned() (*tls.Certificate, error) {
	crtPath := filepath.Join(m.selfDir, "selfsigned.crt")
	keyPath := filepath.Join(m.selfDir, "selfsigned.key")

	if kc, err := tls.LoadX509KeyPair(crtPath, keyPath); err == nil {
		return &kc, nil
	}

	if err := os.MkdirAll(m.selfDir, 0o700); err != nil {
		localDir := "./tls"
		if err2 := os.MkdirAll(localDir, 0o700); err2 == nil {
			m.selfDir = localDir
			crtPath = filepath.Join(m.selfDir, "selfsigned.crt")
			keyPath = filepath.Join(m.selfDir, "selfsigned.key")
		} else {
			return nil, fmt.Errorf("mkdir %s: %w", m.selfDir, err)
		}
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ECDSA key: %w", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		serialNumber = big.NewInt(time.Now().UnixNano())
	}

	tmpl := x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      pkix.Name{CommonName: m.host, Organization: []string{"nasconn+ self-signed"}},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().AddDate(10, 0, 0), // 10 years validity
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{m.host, "localhost"},
	}

	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("create certificate: %w", err)
	}

	crtOut, err := os.OpenFile(crtPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return nil, err
	}
	pem.Encode(crtOut, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	crtOut.Close()

	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}

	keyOut, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, err
	}
	pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})
	keyOut.Close()

	kc, err := tls.LoadX509KeyPair(crtPath, keyPath)
	if err != nil {
		return nil, err
	}
	return &kc, nil
}
