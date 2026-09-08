package cert

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/crypto/acme/autocert"
)

type CertEntry struct {
	Host string `json:"host"`
	Cert string `json:"cert"`
	Key  string `json:"key"`
}

type Manager struct {
	mu           sync.RWMutex
	cfgPath      string
	host         string
	selfDir      string
	fallback     bool
	autoTrust    bool
	acmeEnabled  bool
	acmeDomain   string
	acmeInitErr  error
	autoTrustErr error
	acmeMgr      *autocert.Manager
	cur          *tls.Certificate
	loadedAt     string
	trustedCA    string
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
		} else {
			m.acmeInitErr = fmt.Errorf("initialize ACME cache %s: %w", acmeCacheDir, err)
		}
	}

	return m
}

// GetCertificate implements dynamic certificate resolution for tls.Config
func (m *Manager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if m.acmeEnabled && m.acmeMgr != nil {
		if cert, err := m.acmeMgr.GetCertificate(hello); err == nil && cert != nil {
			return cert, nil
		}
	}

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

// ACMEReady reports whether the configured ACME client can issue a certificate
// during a TLS handshake. Readiness does not imply issuance has completed.
func (m *Manager) ACMEReady() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.acmeEnabled && m.acmeMgr != nil
}

// ACMEInitError returns a non-nil error when ACME was enabled but could not be
// initialized, for example because its persistent cache directory was unusable.
func (m *Manager) ACMEInitError() error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.acmeInitErr
}

// SetAutoTrust controls whether the generated fallback leaf is signed by a
// persistent local CA and that CA is installed in the OS trust store.
func (m *Manager) SetAutoTrust(enabled bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.autoTrust = enabled
}

// AutoTrustEnabled reports whether automatic local CA installation is active.
func (m *Manager) AutoTrustEnabled() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.autoTrust
}

// LocalCATrusted reports whether the current generated local CA is known to be
// trusted by this process. It is best-effort runtime state, not a full system
// certificate store scan.
func (m *Manager) LocalCATrusted() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.trustedCA != ""
}

// LocalCATrustError returns the most recent automatic CA trust setup error.
func (m *Manager) LocalCATrustError() error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.autoTrustErr
}

func (m *Manager) certFingerprint(certFile, keyFile string) string {
	cStat, err1 := os.Stat(certFile)
	kStat, err2 := os.Stat(keyFile)
	if err1 != nil || err2 != nil {
		return fmt.Sprintf("file:%s:%s", certFile, keyFile)
	}
	// #nosec G304 - certFile is controlled by administrator configuration
	data, err := os.ReadFile(filepath.Clean(certFile))
	if err != nil {
		return fmt.Sprintf("file:%s:%d:%d", certFile, cStat.ModTime().UnixNano(), kStat.ModTime().UnixNano())
	}
	h := sha256.Sum256(data)
	return fmt.Sprintf("file:%s:%x:%d:%d", certFile, h[:8], cStat.ModTime().UnixNano(), kStat.ModTime().UnixNano())
}

// Refresh checks whether the certificate needs to be reloaded from disk or regenerated
// It uses copy-on-write: snapshot config under RLock, do IO unlocked, then Lock to swap
func (m *Manager) Refresh() error {
	m.mu.RLock()
	cfgPath := m.cfgPath
	host := m.host
	selfDir := m.selfDir
	fallback := m.fallback
	autoTrust := m.autoTrust
	acmeEnabled := m.acmeEnabled
	acmeMgr := m.acmeMgr
	loadedAtSnap := m.loadedAt
	m.mu.RUnlock()

	var lastErr error

	if cfgPath != "" {
		certFile, keyFile, err := m.resolveCertFilesWith(cfgPath, host)
		if err == nil {
			fp := m.certFingerprint(certFile, keyFile)
			if fp != loadedAtSnap {
				kc, kerr := tls.LoadX509KeyPair(certFile, keyFile)
				if kerr == nil {
					m.mu.Lock()
					if fp != m.loadedAt {
						m.cur = &kc
						m.loadedAt = fp
					}
					m.mu.Unlock()
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

	if fallback {
		sc, newDir, caPath, err := loadOrCreateLocalSignedCertificate(selfDir, host)
		if err == nil && sc != nil {
			// P0-2 FIX: fingerprint the actual on-disk files, not just the
			// host name. A static "self:"+host never changes, so an external
			// rotation (certbot/acme.sh overwriting selfsigned.crt/.key)
			// would be served stale until process restart.
			effDir := selfDir
			if newDir != "" {
				effDir = newDir
			}
			fp := "self:" + m.certFingerprint(
				filepath.Join(effDir, "selfsigned.crt"),
				filepath.Join(effDir, "selfsigned.key"),
			)
			m.mu.Lock()
			if fp != m.loadedAt || m.cur == nil {
				m.cur = sc
				m.loadedAt = fp
				if newDir != "" && newDir != m.selfDir {
					m.selfDir = newDir
				}
			} else if newDir != "" && newDir != m.selfDir {
				m.selfDir = newDir
			}
			shouldReturn := !acmeEnabled
			m.mu.Unlock()
			if autoTrust {
				trustErr := m.ensureLocalCATrusted(caPath)
				m.mu.Lock()
				m.autoTrustErr = trustErr
				m.mu.Unlock()
				if trustErr != nil {
					lastErr = trustErr
				}
			}
			if shouldReturn {
				return lastErr
			}
		} else if err != nil {
			lastErr = fmt.Errorf("generate self-signed: %w", err)
		}
	}

	if acmeEnabled && acmeMgr != nil {
		// Don't mask a total failure: only swallow the error while we still
		// have a usable certificate to serve. With no cert at all, surface
		// lastErr so the operator sees it instead of silent handshake fails.
		m.mu.RLock()
		hasCurForACME := m.cur != nil
		m.mu.RUnlock()
		if hasCurForACME {
			return nil
		}
	} else if acmeEnabled && acmeMgr == nil {
		if initErr := m.ACMEInitError(); initErr != nil {
			lastErr = initErr
		} else {
			lastErr = fmt.Errorf("ACME is enabled but no domain is configured")
		}
	}

	m.mu.RLock()
	hasCur := m.cur != nil
	m.mu.RUnlock()
	if hasCur {
		return nil
	}

	if lastErr == nil {
		lastErr = fmt.Errorf("no certificate source configured and self-signed fallback disabled")
	}
	return lastErr
}

func (m *Manager) resolveCertFilesWith(cfgPath, host string) (string, string, error) {
	// #nosec G304 - cfgPath is controlled by administrator configuration
	b, err := os.ReadFile(filepath.Clean(cfgPath))
	if err != nil {
		return "", "", err
	}

	var entries []CertEntry
	if err := json.Unmarshal(b, &entries); err == nil && len(entries) > 0 {
		for _, want := range []string{host, "fallback", "*"} {
			for _, e := range entries {
				if e.Host == want && e.Cert != "" && e.Key != "" {
					return e.Cert, e.Key, nil
				}
			}
		}
		return "", "", fmt.Errorf("cert for host %q not found in %s", host, cfgPath)
	}

	return "", "", fmt.Errorf("invalid cert config format in %s", cfgPath)
}
