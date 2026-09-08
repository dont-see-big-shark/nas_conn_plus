package cert

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"
)

const (
	localCACertFile = "nasconnplus-local-ca.crt"
	localCAKeyFile  = "nasconnplus-local-ca.key"
	localCACPName   = "nasconn+ Local CA"
)

type managedLocalCA struct {
	cert     *x509.Certificate
	key      *ecdsa.PrivateKey
	certPath string
	keyPath  string
}

var (
	localCATrustProbe    = probeLocalCATrust
	localCATrustInstall  = installLocalCATrust
	linuxCACertInstaller = updateLinuxCACertificates
)

func ensureCertDir(preferred string) (string, error) {
	if err := os.MkdirAll(preferred, 0o700); err == nil {
		return preferred, nil
	}

	fallback := "./tls"
	if err := os.MkdirAll(fallback, 0o700); err != nil {
		return "", fmt.Errorf("mkdir %s: %w", preferred, err)
	}
	return fallback, nil
}

func parsePEMCertificate(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("no certificate PEM in %s", path)
	}
	return x509.ParseCertificate(block.Bytes)
}

func parsePEMECPrivateKey(path string) (*ecdsa.PrivateKey, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "EC PRIVATE KEY" {
		return nil, fmt.Errorf("no EC private key PEM in %s", path)
	}
	return x509.ParseECPrivateKey(block.Bytes)
}

func writePEM(path, blockType string, der []byte) error {
	f, err := os.OpenFile(filepath.Clean(path), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if err := pem.Encode(f, &pem.Block{Type: blockType, Bytes: der}); err != nil {
		_ = f.Close()
		return fmt.Errorf("encode %s: %w", blockType, err)
	}
	return f.Close()
}

func randomSerialNumber() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, err
	}
	return serial, nil
}

func loadOrCreateLocalCA(dir string) (*managedLocalCA, error) {
	ca := &managedLocalCA{
		certPath: filepath.Join(dir, localCACertFile),
		keyPath:  filepath.Join(dir, localCAKeyFile),
	}

	cert, certErr := parsePEMCertificate(ca.certPath)
	key, keyErr := parsePEMECPrivateKey(ca.keyPath)
	if certErr == nil && keyErr == nil && cert.IsCA &&
		cert.CheckSignatureFrom(cert) == nil {
		ca.cert = cert
		ca.key = key
		return ca, nil
	}

	ca.key, keyErr = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if keyErr != nil {
		return nil, fmt.Errorf("generate local CA key: %w", keyErr)
	}
	serial, err := randomSerialNumber()
	if err != nil {
		return nil, fmt.Errorf("generate local CA serial: %w", err)
	}

	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: localCACPName, Organization: []string{"nasconn+ local trust"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(3650 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &ca.key.PublicKey, ca.key)
	if err != nil {
		return nil, fmt.Errorf("create local CA certificate: %w", err)
	}
	if err := writePEM(ca.certPath, "CERTIFICATE", der); err != nil {
		return nil, fmt.Errorf("write local CA certificate: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(ca.key)
	if err != nil {
		return nil, fmt.Errorf("marshal local CA key: %w", err)
	}
	if err := writePEM(ca.keyPath, "EC PRIVATE KEY", keyDER); err != nil {
		return nil, fmt.Errorf("write local CA key: %w", err)
	}

	ca.cert, err = parsePEMCertificate(ca.certPath)
	if err != nil {
		return nil, fmt.Errorf("reload local CA certificate: %w", err)
	}
	return ca, nil
}

func leafMatchesCA(leaf, ca *x509.Certificate) bool {
	if leaf == nil || ca == nil || !bytes.Equal(leaf.RawIssuer, ca.RawSubject) {
		return false
	}
	return leaf.CheckSignatureFrom(ca) == nil
}

func buildLocalLeafTemplate(host string) (*x509.Certificate, error) {
	serial, err := randomSerialNumber()
	if err != nil {
		return nil, fmt.Errorf("generate certificate serial: %w", err)
	}

	ips := make([]net.IP, 0, 3)
	for _, candidate := range []net.IP{net.ParseIP(host), net.ParseIP("127.0.0.1"), net.ParseIP("::1")} {
		if candidate == nil {
			continue
		}
		duplicate := false
		for _, existing := range ips {
			if existing.Equal(candidate) {
				duplicate = true
				break
			}
		}
		if !duplicate {
			ips = append(ips, candidate)
		}
	}

	dnsNames := []string{"localhost"}
	if host != "" && net.ParseIP(host) == nil && host != "localhost" {
		dnsNames = append(dnsNames, host)
	}

	return &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: host, Organization: []string{"nasconn+ local certificate"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(825 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              dnsNames,
		IPAddresses:           ips,
	}, nil
}

func createLocalLeaf(ca *managedLocalCA, host, crtPath, keyPath string) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate certificate key: %w", err)
	}
	tmpl, err := buildLocalLeafTemplate(host)
	if err != nil {
		return nil, err
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		return nil, fmt.Errorf("create certificate: %w", err)
	}
	if err := writePEM(crtPath, "CERTIFICATE", der); err != nil {
		return nil, fmt.Errorf("write certificate: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal certificate key: %w", err)
	}
	if err := writePEM(keyPath, "EC PRIVATE KEY", keyDER); err != nil {
		return nil, fmt.Errorf("write certificate key: %w", err)
	}

	kc, err := tls.LoadX509KeyPair(crtPath, keyPath)
	if err != nil {
		return nil, err
	}
	return &kc, nil
}

func loadOrCreateLocalSignedCertificate(selfDir, host string) (*tls.Certificate, string, string, error) {
	dir, err := ensureCertDir(selfDir)
	if err != nil {
		return nil, "", "", err
	}
	ca, err := loadOrCreateLocalCA(dir)
	if err != nil {
		return nil, "", "", err
	}

	crtPath := filepath.Join(dir, "selfsigned.crt")
	keyPath := filepath.Join(dir, "selfsigned.key")
	if kc, err := tls.LoadX509KeyPair(crtPath, keyPath); err == nil {
		leaf, parseErr := x509.ParseCertificate(kc.Certificate[0])
		if parseErr == nil && leafMatchesCA(leaf, ca.cert) {
			return &kc, dir, ca.certPath, nil
		}
	}

	kc, err := createLocalLeaf(ca, host, crtPath, keyPath)
	if err != nil {
		return nil, "", "", err
	}
	return kc, dir, ca.certPath, nil
}

func (m *Manager) ensureLocalCATrusted(caPath string) error {
	fingerprint, err := caFileFingerprint(caPath)
	if err != nil {
		return fmt.Errorf("fingerprint local CA: %w", err)
	}

	m.mu.RLock()
	alreadyKnown := m.trustedCA == fingerprint
	m.mu.RUnlock()
	if alreadyKnown {
		return nil
	}

	trusted, err := localCATrustProbe(caPath)
	if err != nil {
		return err
	}
	if !trusted {
		if err := localCATrustInstall(caPath); err != nil {
			return err
		}
	}

	m.mu.Lock()
	m.trustedCA = fingerprint
	m.mu.Unlock()
	return nil
}

func caFileFingerprint(path string) (string, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return fmt.Sprintf("local-ca:sha256:%x", sum), nil
}

func probeLocalCATrust(caPath string) (bool, error) {
	switch runtime.GOOS {
	case "darwin":
		if _, err := exec.LookPath("security"); err != nil {
			return false, fmt.Errorf("security tool unavailable: %w", err)
		}
		// #nosec G204 - caPath is the managed local CA path and is passed as a
		// fixed argument to the fixed security subcommand.
		cmd := exec.Command("security", "verify-cert", "-c", caPath, "-p", "ssl")
		if err := cmd.Run(); err != nil {
			return false, nil
		}
		return true, nil
	case "linux":
		installed, err := os.ReadFile(filepath.Clean("/usr/local/share/ca-certificates/" + localCACertFile))
		if err != nil {
			return false, nil
		}
		current, err := os.ReadFile(filepath.Clean(caPath))
		if err != nil {
			return false, err
		}
		return bytes.Equal(installed, current), nil
	default:
		return false, fmt.Errorf("automatic local CA trust is not supported on %s", runtime.GOOS)
	}
}

func installLocalCATrust(caPath string) error {
	switch runtime.GOOS {
	case "darwin":
		home, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		keychain := filepath.Join(home, "Library", "Keychains", "login.keychain-db")
		args := []string{"add-trusted-cert", "-r", "trustRoot", "-p", "ssl"}
		if _, statErr := os.Stat(keychain); statErr == nil {
			args = append(args, "-k", keychain)
		}
		args = append(args, caPath)
		cmd := exec.Command("security", args...)
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("trust local CA in macOS keychain: %w: %s", err, string(output))
		}
		return nil
	case "linux":
		data, err := os.ReadFile(filepath.Clean(caPath))
		if err != nil {
			return err
		}
		destination := filepath.Clean("/usr/local/share/ca-certificates/" + localCACertFile)
		if err := os.MkdirAll(filepath.Dir(destination), 0o750); err != nil {
			return fmt.Errorf("create system CA directory: %w", err)
		}
		// #nosec G703 - destination is a fixed system path with a constant file name.
		if err := os.WriteFile(destination, data, 0o600); err != nil {
			return fmt.Errorf("install local CA certificate: %w", err)
		}
		return linuxCACertInstaller()
	default:
		return fmt.Errorf("automatic local CA trust is not supported on %s", runtime.GOOS)
	}
}

func updateLinuxCACertificates() error {
	if _, err := exec.LookPath("update-ca-certificates"); err != nil {
		return fmt.Errorf("update-ca-certificates unavailable: %w", err)
	}
	cmd := exec.Command("update-ca-certificates")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("refresh system CA trust: %w: %s", err, string(output))
	}
	return nil
}
