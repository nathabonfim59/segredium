// Package ca is segredium's built-in local certificate authority.
//
// A self-signed ECDSA P-256 root is kept as ca.crt.pem/ca.key.pem in tls.ca_dir. The HTTPS
// listener asks the CA for a certificate during the TLS handshake (SNI) and the CA mints and
// caches a short-lived leaf for the requested hostname. Redirecting
// secretsmanager.<region>.amazonaws.com to segredium in /etc/hosts therefore works with any
// stock SDK once the root certificate is trusted.
//
// It implements api.TLSProvider (tls.mode=ca), wired in internal/app/wire_tls.go.
package ca

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/nathabonfim59/segredium/internal/config"
)

const (
	// CertFileName is the root certificate's PEM file inside Options.Dir.
	CertFileName = "ca.crt.pem"
	// KeyFileName is the root private key's PEM file inside Options.Dir.
	KeyFileName = "ca.key.pem"

	// DefaultCACommonName is the root certificate's subject CN.
	DefaultCACommonName = "segredium local CA"
	// DefaultCAValidity is the root certificate's lifetime.
	DefaultCAValidity = 10 * 365 * 24 * time.Hour
	// DefaultLeafValidity is how long a minted leaf is valid. Short-lived leaves are
	// re-minted from the long-lived root, so a leaked leaf goes stale quickly.
	DefaultLeafValidity = 24 * time.Hour
	maxCachedLeaves     = 64
)

// endpointRe is the allowlist for minted leaves: only AWS Secrets Manager endpoint names.
// The CA must never sign arbitrary hostnames, even if someone points them at the server.
var endpointRe = regexp.MustCompile(`^secretsmanager(?:-fips)?\.[a-z]{2}(?:-[a-z]+)+-[0-9]{1,2}\.(?:amazonaws\.com|amazonaws\.com\.cn|api\.aws|api\.amazonwebservices\.com\.cn)$`)

// Options configures a CA. Dir is required; the other fields have defaults.
type Options struct {
	// Dir holds the root certificate and key.
	Dir string
	// CommonName is the root certificate's subject CN.
	CommonName string
	// Validity is the root certificate's lifetime.
	Validity time.Duration
	// DefaultRegion names the endpoint minted when a client sends no SNI (e.g. dialing
	// an IP address). Empty makes such handshakes fail instead.
	DefaultRegion string
	// LeafValidity overrides DefaultLeafValidity for minted certificates.
	LeafValidity time.Duration
	// Now is the time source (tests inject a fake clock); defaults to time.Now.
	Now func() time.Time
	// Rand is the randomness source for keys and serial numbers; defaults to crypto/rand.
	Rand io.Reader
}

func (o Options) withDefaults() Options {
	if o.CommonName == "" {
		o.CommonName = DefaultCACommonName
	}
	if o.Validity <= 0 {
		o.Validity = DefaultCAValidity
	}
	if o.Now == nil {
		o.Now = func() time.Time { return time.Now().UTC() }
	}
	if o.Rand == nil {
		o.Rand = rand.Reader
	}
	if o.LeafValidity <= 0 {
		o.LeafValidity = DefaultLeafValidity
	}
	return o
}

// CA is a loaded root certificate authority. It is safe for concurrent use.
type CA struct {
	opts    Options
	cert    *x509.Certificate
	certPEM []byte
	key     crypto.Signer

	mu    sync.Mutex
	cache map[string]*tls.Certificate
}

// NewCA loads the CA configured by cfg.TLS, creating and persisting a new root if none exists
// yet ("auto-created on serve"). A partially written CA is an error, never silently replaced.
func NewCA(cfg *config.Config) (*CA, error) {
	if cfg == nil {
		return nil, errors.New("ca: nil config")
	}
	return Ensure(Options{
		Dir:           cfg.TLS.CADir,
		CommonName:    cfg.TLS.CACommonName,
		Validity:      cfg.TLS.CAValidity,
		DefaultRegion: cfg.Server.DefaultRegion,
	})
}

// Ensure loads the CA in opts.Dir, creating a new root when nothing is there yet.
func Ensure(opts Options) (*CA, error) {
	c, err := Load(opts)
	if err == nil {
		return c, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return Create(opts)
}

// Create generates a new root CA in opts.Dir. Existing root files are never replaced,
// including when two server processes try to initialize the directory concurrently.
func Create(opts Options) (*CA, error) {
	opts = opts.withDefaults()
	if err := checkDir(opts.Dir); err != nil {
		return nil, err
	}
	for _, name := range []string{KeyFileName, CertFileName} {
		if _, err := os.Lstat(filepath.Join(opts.Dir, name)); !errors.Is(err, os.ErrNotExist) {
			if err != nil {
				return nil, fmt.Errorf("ca: check %s: %w", name, err)
			}
			return nil, fmt.Errorf("ca: %s already exists; refusing to replace the CA", name)
		}
	}
	now := opts.Now()
	key, err := ecdsa.GenerateKey(elliptic.P256(), opts.Rand)
	if err != nil {
		return nil, fmt.Errorf("ca: generate root key: %w", err)
	}
	serial, err := serialNumber(opts.Rand)
	if err != nil {
		return nil, err
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("ca: encode root public key: %w", err)
	}
	ski := sha1.Sum(spki)
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: opts.CommonName, Organization: []string{"segredium"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(opts.Validity),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		SubjectKeyId:          ski[:],
	}
	der, err := x509.CreateCertificate(opts.Rand, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("ca: create root certificate: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("ca: encode root key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	if err := os.MkdirAll(opts.Dir, 0o700); err != nil {
		return nil, fmt.Errorf("ca: create %s: %w", opts.Dir, err)
	}
	// Publish the key first. Interrupted initialization stays detectable and needs
	// explicit recovery rather than silently replacing either part of the root.
	if err := writeFile(filepath.Join(opts.Dir, KeyFileName), keyPEM, 0o600); err != nil {
		return nil, err
	}
	if err := writeFile(filepath.Join(opts.Dir, CertFileName), certPEM, 0o644); err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("ca: parse root certificate: %w", err)
	}
	return &CA{opts: opts, cert: cert, certPEM: certPEM, key: key, cache: map[string]*tls.Certificate{}}, nil
}

// Load reads an existing CA from opts.Dir. Only a directory with neither root file
// is reported as os.ErrNotExist, so Ensure can distinguish absent and broken CAs.
func Load(opts Options) (*CA, error) {
	opts = opts.withDefaults()
	if err := checkDir(opts.Dir); err != nil {
		return nil, err
	}
	certPath := filepath.Join(opts.Dir, CertFileName)
	keyPath := filepath.Join(opts.Dir, KeyFileName)
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			if _, keyErr := os.Lstat(keyPath); keyErr == nil {
				return nil, fmt.Errorf("ca: %s exists but %s is missing", KeyFileName, CertFileName)
			} else if !errors.Is(keyErr, os.ErrNotExist) {
				return nil, fmt.Errorf("ca: check %s: %w", keyPath, keyErr)
			}
		}
		return nil, fmt.Errorf("ca: read %s: %w", certPath, err)
	}
	st, err := os.Lstat(keyPath)
	if err != nil {
		return nil, fmt.Errorf("ca: %s exists but cannot access %s: %v", CertFileName, KeyFileName, err)
	}
	if !st.Mode().IsRegular() || st.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("ca: %s must be a regular file accessible only by its owner (chmod 600)", keyPath)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// A certificate without its key is a broken CA, not an absent one: never
			// let Ensure replace it, or every client trusting the old root breaks.
			return nil, fmt.Errorf("ca: %s exists but %s is missing", CertFileName, KeyFileName)
		}
		return nil, fmt.Errorf("ca: read %s: %w", keyPath, err)
	}

	cert, err := parseCert(certPEM)
	if err != nil {
		return nil, fmt.Errorf("ca: %s: %w", certPath, err)
	}
	if !cert.IsCA || !cert.BasicConstraintsValid || cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, fmt.Errorf("ca: %s: certificate is not a signing CA", certPath)
	}
	if now := opts.Now(); now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
		return nil, fmt.Errorf("ca: %s: root certificate is outside its validity period", certPath)
	}
	key, err := parseKey(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("ca: %s: %w", keyPath, err)
	}
	if err := keyMatches(cert, key); err != nil {
		return nil, fmt.Errorf("ca: %s and %s: %w", CertFileName, KeyFileName, err)
	}
	return &CA{opts: opts, cert: cert, certPEM: certPEM, key: key, cache: map[string]*tls.Certificate{}}, nil
}

func checkDir(dir string) error {
	if strings.TrimSpace(dir) == "" {
		return errors.New("ca: directory is required")
	}
	return nil
}

func parseCert(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("no CERTIFICATE PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}
	return cert, nil
}

func parseKey(keyPEM []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, errors.New("no PRIVATE KEY PEM block")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	key, ok := parsed.(crypto.Signer)
	if !ok {
		return nil, errors.New("unsupported private key type")
	}
	return key, nil
}

func keyMatches(cert *x509.Certificate, key crypto.Signer) error {
	want, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return err
	}
	got, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return err
	}
	if !bytes.Equal(want, got) {
		return errors.New("private key does not match certificate")
	}
	return nil
}

func writeFile(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".segredium-ca-*")
	if err != nil {
		return fmt.Errorf("ca: write %s: %w", path, err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("ca: write %s: %w", path, err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("ca: write %s: %w", path, err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("ca: write %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("ca: write %s: %w", path, err)
	}
	// Linking publishes the complete file atomically and refuses an existing target.
	// Rename would silently overwrite another process's root or a partial CA.
	if err := os.Link(tmpName, path); err != nil {
		return fmt.Errorf("ca: write %s: %w", path, err)
	}
	return nil
}

// Dir returns the directory holding the root files.
func (c *CA) Dir() string { return c.opts.Dir }

// ExportPEM returns a copy of the root certificate in PEM form (what clients must trust).
func (c *CA) ExportPEM() []byte { return bytes.Clone(c.certPEM) }

// Certificate returns the parsed root certificate.
func (c *CA) Certificate() *x509.Certificate { return c.cert }

// Fingerprint returns the root certificate's SHA-256 fingerprint in colon-separated hex.
func (c *CA) Fingerprint() string {
	sum := sha256.Sum256(c.cert.Raw)
	parts := make([]string, len(sum))
	for i, b := range sum {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, ":")
}

// TLSConfig implements api.TLSProvider. Certificates are minted on demand from the ClientHello.
func (c *CA) TLSConfig() (*tls.Config, error) {
	return &tls.Config{
		MinVersion:     tls.VersionTLS12,
		GetCertificate: c.getCertificate,
	}, nil
}

// getCertificate answers the handshake with a leaf valid for the SNI hostname. Without SNI it
// falls back to the default region's endpoint so clients that dial an IP still complete the
// handshake (they can only verify it with the hostname or a custom verifier anyway).
func (c *CA) getCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(hello.ServerName), "."))
	if host == "" {
		if c.opts.DefaultRegion == "" {
			return nil, errors.New("ca: client sent no SNI and no default region is configured")
		}
		host = "secretsmanager." + c.opts.DefaultRegion + ".amazonaws.com"
	}
	if !allowedHost(host) {
		return nil, fmt.Errorf("ca: refusing to mint a certificate for %q: only AWS Secrets Manager endpoints and localhost are allowed", host)
	}
	return c.leaf(host)
}

func allowedHost(host string) bool {
	switch host {
	case "localhost", "127.0.0.1":
		return true
	}
	return endpointRe.MatchString(host)
}

func (c *CA) leaf(host string) (*tls.Certificate, error) {
	now := c.opts.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if now.Before(c.cert.NotBefore) || !now.Before(c.cert.NotAfter) {
		return nil, errors.New("ca: root certificate is outside its validity period")
	}
	if cached, ok := c.cache[host]; ok {
		// Renew before the final third of the certificate's actual lifetime, including
		// backdating and any truncation at the root's expiry.
		lifetime := cached.Leaf.NotAfter.Sub(cached.Leaf.NotBefore)
		if cached.Leaf.NotAfter.Sub(now) >= lifetime/3 {
			return cached, nil
		}
	}
	for name, cert := range c.cache {
		if !now.Before(cert.Leaf.NotAfter) {
			delete(c.cache, name)
		}
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), c.opts.Rand)
	if err != nil {
		return nil, fmt.Errorf("ca: generate leaf key for %s: %w", host, err)
	}
	serial, err := serialNumber(c.opts.Rand)
	if err != nil {
		return nil, err
	}
	notAfter := now.Add(c.opts.LeafValidity)
	if notAfter.After(c.cert.NotAfter) {
		notAfter = c.cert.NotAfter
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: host, Organization: []string{"segredium"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		AuthorityKeyId:        c.cert.SubjectKeyId,
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(c.opts.Rand, tmpl, c.cert, &key.PublicKey, c.key)
	if err != nil {
		return nil, fmt.Errorf("ca: sign leaf for %s: %w", host, err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("ca: parse leaf for %s: %w", host, err)
	}
	cert := &tls.Certificate{Certificate: [][]byte{der, c.cert.Raw}, PrivateKey: key, Leaf: parsed}
	if len(c.cache) >= maxCachedLeaves {
		// A bounded scan needs no timers, goroutines, or additional cache metadata.
		var oldest string
		for name, cached := range c.cache {
			if oldest == "" || cached.Leaf.NotAfter.Before(c.cache[oldest].Leaf.NotAfter) {
				oldest = name
			}
		}
		delete(c.cache, oldest)
	}
	c.cache[host] = cert
	return cert, nil
}

func serialNumber(r io.Reader) (*big.Int, error) {
	serial, err := rand.Int(r, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("ca: generate serial number: %w", err)
	}
	if serial.Sign() == 0 {
		serial = big.NewInt(1)
	}
	return serial, nil
}
