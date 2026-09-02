package cert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
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
	mu          sync.RWMutex
	cfgPath     string
	host        string
	selfDir     string
	fallback    bool
	acmeEnabled bool
	acmeDomain  string
	acmeMgr     *autocert.Manager
	cur         *tls.Certificate
	loadedAt    string
}

// NewManager creates a new TLS certificate manager with optional ACME support
func NewManager(cfgPath, host, selfDir string, fallback bool, acmeEnabled bool, acmeDomain, acmeEmail, acmeCacheDir string) *Manager {
	m := &Manager{
		cfgPath:     cfgPath,
		host:        host,
		selfDir:     selfDir,
		fallback:    fallback,
		acmeEnabled: acmeEnabled,
		acmeDomain:  acmeDomain,
	}

	if acmeEnabled && acmeDomain != "" {
		if err := os.MkdirAll(acmeCacheDir, 0o700); err == nil {
			m.acmeMgr = &autocert.Manager{
				Prompt:     autocert.AcceptTOS,
				HostPolicy: autocert.HostWhitelist(acmeDomain),
				Cache:      autocert.DirCache(acmeCacheDir),
				Email:      acmeEmail,
			}
		}
	}

	return m
}

// GetCertificate implements dynamic certificate resolution for tls.Config
func (m *Manager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	// 1. If ACME is active, delegate to autocert manager
	if m.acmeEnabled && m.acmeMgr != nil {
		if cert, err := m.acmeMgr.GetCertificate(hello); err == nil && cert != nil {
			return cert, nil
		}
	}

	// 2. Return currently loaded certificate (from config file or self-signed)
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.cur != nil {
		return m.cur, nil
	}

	return nil, fmt.Errorf("no certificate available for %s", hello.ServerName)
}

// Current returns the currently active certificate, if any
func (m *Manager) Current() *tls.Certificate {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cur
}

func (m *Manager) certFingerprint(certFile, keyFile string) string {
	cStat, err1 := os.Stat(certFile)
	kStat, err2 := os.Stat(keyFile)
	if err1 != nil || err2 != nil {
		return fmt.Sprintf("file:%s:%s", certFile, keyFile)
	}
	data, err := os.ReadFile(certFile)
	if err != nil {
		return fmt.Sprintf("file:%s:%d:%d", certFile, cStat.ModTime().UnixNano(), kStat.ModTime().UnixNano())
	}
	h := sha256.Sum256(data)
	return fmt.Sprintf("file:%s:%x:%d", certFile, h[:8], cStat.ModTime().UnixNano())
}

// Refresh checks whether the certificate needs to be reloaded from disk or regenerated
func (m *Manager) Refresh() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var lastErr error

	// Try loading from cert_config_path if provided
	if m.cfgPath != "" {
		certFile, keyFile, err := m.resolveCertFiles()
		if err == nil {
			fp := m.certFingerprint(certFile, keyFile)
			if fp != m.loadedAt {
				kc, kerr := tls.LoadX509KeyPair(certFile, keyFile)
				if kerr == nil {
					m.cur = &kc
					m.loadedAt = fp
					return nil
				}
				lastErr = fmt.Errorf("load keypair from %s: %w", certFile, kerr)
			} else {
				return nil
			}
		} else {
			lastErr = err
		}
	}

	// Fallback to self-signed certificate if allowed (even if ACME is enabled, as initial bootstrap)
	if m.fallback {
		sc, err := m.loadOrCreateSelfSigned()
		if err == nil && sc != nil {
			fp := "self:" + m.host
			if fp != m.loadedAt || m.cur == nil {
				m.cur = sc
				m.loadedAt = fp
			}
			if !m.acmeEnabled {
				return nil
			}
		} else if err != nil {
			lastErr = fmt.Errorf("generate self-signed: %w", err)
		}
	}

	// If ACME is enabled, we don't strictly require a static certificate
	if m.acmeEnabled && m.acmeMgr != nil {
		return nil
	}

	if m.cur != nil {
		return nil
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
				if e.Host == want && e.Cert != "" && e.Key != "" {
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

	var ips []net.IP
	if ip := net.ParseIP(m.host); ip != nil {
		ips = append(ips, ip)
	}
	ips = append(ips, net.ParseIP("127.0.0.1"), net.ParseIP("::1"))

	dnsNames := []string{"localhost"}
	if net.ParseIP(m.host) == nil && m.host != "" {
		dnsNames = append(dnsNames, m.host)
	}

	tmpl := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{CommonName: m.host, Organization: []string{"nasconn+ self-signed"}},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0), // 10 years validity
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              dnsNames,
		IPAddresses:           ips,
	}

	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("create certificate: %w", err)
	}

	crtOut, err := os.OpenFile(crtPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return nil, err
	}
	if err := pem.Encode(crtOut, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		crtOut.Close()
		return nil, fmt.Errorf("encode certificate: %w", err)
	}
	crtOut.Close()

	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}

	keyOut, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, err
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}); err != nil {
		keyOut.Close()
		return nil, fmt.Errorf("encode private key: %w", err)
	}
	keyOut.Close()

	kc, err := tls.LoadX509KeyPair(crtPath, keyPath)
	if err != nil {
		return nil, err
	}
	return &kc, nil
}
