package ca

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/nathabonfim59/segredium/internal/config"
)

func testCA(t *testing.T) *CA {
	t.Helper()
	cfg := config.Default()
	cfg.TLS.CADir = t.TempDir()
	c, err := NewCA(cfg)
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	return c
}

func verifyLeaf(t *testing.T, c *CA, cert *tls.Certificate, dnsName string) *x509.Certificate {
	t.Helper()
	if len(cert.Certificate) != 2 {
		t.Fatalf("chain length = %d, want leaf+CA", len(cert.Certificate))
	}
	if !bytes.Equal(cert.Certificate[1], c.Certificate().Raw) {
		t.Fatal("chain does not include the root certificate")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(c.Certificate())
	if _, err := leaf.Verify(x509.VerifyOptions{
		DNSName:   dnsName,
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		t.Fatalf("leaf does not verify for %s: %v", dnsName, err)
	}
	if leaf.Subject.CommonName != dnsName {
		t.Fatalf("leaf CN = %q, want %q", leaf.Subject.CommonName, dnsName)
	}
	if delta := leaf.NotAfter.Sub(leaf.NotBefore); delta < 23*time.Hour || delta > 26*time.Hour {
		t.Fatalf("leaf validity = %v, want ~24h", delta)
	}
	return leaf
}

func TestNewCAGeneratesAndReloads(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default()
	cfg.TLS.CADir = dir // NewCA auto-creates on serve
	c, err := NewCA(cfg)
	if err != nil {
		t.Fatalf("NewCA (create): %v", err)
	}
	root := c.Certificate()
	if !root.IsCA || root.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Fatal("root is not a signing CA")
	}
	if root.Subject.CommonName != DefaultCACommonName {
		t.Fatalf("root CN = %q", root.Subject.CommonName)
	}

	certPath := filepath.Join(dir, CertFileName)
	keyPath := filepath.Join(dir, KeyFileName)
	if st, err := os.Stat(certPath); err != nil || st.Mode().Perm() != 0o644 {
		t.Fatalf("cert file: %v mode %v", err, st.Mode().Perm())
	}
	if st, err := os.Stat(keyPath); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("key file: %v mode %v", err, st.Mode().Perm())
	}

	again, err := NewCA(cfg)
	if err != nil {
		t.Fatalf("NewCA (load): %v", err)
	}
	if !bytes.Equal(c.ExportPEM(), again.ExportPEM()) {
		t.Fatal("second NewCA replaced the existing CA")
	}
	if !bytes.Equal(c.ExportPEM(), mustRead(t, certPath)) {
		t.Fatal("ExportPEM differs from the stored certificate")
	}
}

func TestNewCADoesNotReplaceBrokenCA(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default()
	cfg.TLS.CADir = dir
	if _, err := NewCA(cfg); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, KeyFileName)); err != nil {
		t.Fatal(err)
	}
	if _, err := NewCA(cfg); err == nil {
		t.Fatal("NewCA replaced a CA whose key is missing")
	}
}

func TestEnsurePreservesOrphanedKey(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, KeyFileName)
	original := []byte("existing private key")
	if err := os.WriteFile(keyPath, original, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Ensure(Options{Dir: dir}); err == nil {
		t.Fatal("Ensure replaced an orphaned private key")
	}
	if !bytes.Equal(mustRead(t, keyPath), original) {
		t.Fatal("orphaned key changed")
	}
}

func TestLoadRejectsInsecureKeyPermissions(t *testing.T) {
	c := testCA(t)
	if err := os.Chmod(filepath.Join(c.Dir(), KeyFileName), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(Options{Dir: c.Dir()}); err == nil {
		t.Fatal("Load accepted a private key readable by other users")
	}
}

func TestExpiredRootIsRejected(t *testing.T) {
	now := time.Now().UTC()
	c, err := Create(Options{Dir: t.TempDir(), Validity: time.Hour, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Hour)
	if _, err := Load(Options{Dir: c.Dir(), Now: func() time.Time { return now }}); err == nil {
		t.Error("Load accepted an expired root")
	}
	tc, _ := c.TLSConfig()
	if _, err := tc.GetCertificate(&tls.ClientHelloInfo{ServerName: "localhost"}); err == nil {
		t.Error("minted a leaf from an expired root")
	}
}

func TestCreateDoesNotReplaceExistingCA(t *testing.T) {
	c := testCA(t)
	original := c.ExportPEM()
	if _, err := Create(Options{Dir: c.Dir()}); err == nil {
		t.Fatal("Create replaced an existing root")
	}
	if !bytes.Equal(mustRead(t, filepath.Join(c.Dir(), CertFileName)), original) {
		t.Fatal("root changed")
	}
}

func TestLeafCacheIsBounded(t *testing.T) {
	c := testCA(t)
	tc, _ := c.TLSConfig()
	for i := 0; i < 70; i++ {
		host := fmt.Sprintf("secretsmanager.us-test-%d.amazonaws.com", i)
		if _, err := tc.GetCertificate(&tls.ClientHelloInfo{ServerName: host}); err != nil {
			t.Fatal(err)
		}
	}
	if len(c.cache) > 64 {
		t.Fatalf("cache contains %d leaves, want at most 64", len(c.cache))
	}
}

func TestLeafCacheEvictsExpiredEntries(t *testing.T) {
	now := time.Now().UTC()
	c, err := Ensure(Options{Dir: t.TempDir(), Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.leaf("localhost"); err != nil {
		t.Fatal(err)
	}
	now = now.Add(DefaultLeafValidity + time.Minute)
	if _, err := c.leaf("secretsmanager.us-east-1.amazonaws.com"); err != nil {
		t.Fatal(err)
	}
	if _, ok := c.cache["localhost"]; ok {
		t.Fatal("expired leaf remained in the cache")
	}
}

func TestMintAllowedHosts(t *testing.T) {
	c := testCA(t)
	tc, err := c.TLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	hosts := []string{
		"secretsmanager.us-east-1.amazonaws.com",
		"secretsmanager-fips.us-west-2.amazonaws.com",
		"secretsmanager.eu-central-1.api.aws",
		"secretsmanager.cn-north-1.amazonaws.com.cn",
		"secretsmanager.cn-north-1.api.amazonwebservices.com.cn",
		"localhost",
		"127.0.0.1",
	}
	for _, host := range hosts {
		cert, err := tc.GetCertificate(&tls.ClientHelloInfo{ServerName: host})
		if err != nil {
			t.Fatalf("%s: %v", host, err)
		}
		verifyLeaf(t, c, cert, host)
	}
}

func TestMintIsCached(t *testing.T) {
	c := testCA(t)
	tc, _ := c.TLSConfig()
	first, err := tc.GetCertificate(&tls.ClientHelloInfo{ServerName: "secretsmanager.us-east-1.amazonaws.com"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := tc.GetCertificate(&tls.ClientHelloInfo{ServerName: "secretsmanager.us-east-1.amazonaws.com"})
	if err != nil {
		t.Fatal(err)
	}
	if &first.Certificate[0][0] != &second.Certificate[0][0] {
		t.Fatal("leaf was re-minted inside its validity")
	}
}

func TestMintRefreshesExpiredLeaf(t *testing.T) {
	now := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	c, err := Ensure(Options{
		Dir:           t.TempDir(),
		DefaultRegion: "us-east-1",
		Now:           func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	tc, _ := c.TLSConfig()
	hello := &tls.ClientHelloInfo{ServerName: "secretsmanager.us-east-1.amazonaws.com"}
	first, err := tc.GetCertificate(hello)
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(DefaultLeafValidity + time.Minute)
	second, err := tc.GetCertificate(hello)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first.Certificate[0], second.Certificate[0]) {
		t.Fatal("expired leaf was not refreshed")
	}
}

func TestMintRefreshesLeafBelowOneThirdLifetime(t *testing.T) {
	for _, validity := range []time.Duration{DefaultLeafValidity, 3 * time.Hour} {
		t.Run(validity.String(), func(t *testing.T) {
			now := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
			c, err := Ensure(Options{Dir: t.TempDir(), LeafValidity: validity, Now: func() time.Time { return now }})
			if err != nil {
				t.Fatal(err)
			}
			tc, _ := c.TLSConfig()
			hello := &tls.ClientHelloInfo{ServerName: "secretsmanager.us-east-1.amazonaws.com"}
			first, err := tc.GetCertificate(hello)
			if err != nil {
				t.Fatal(err)
			}
			lifetime := first.Leaf.NotAfter.Sub(first.Leaf.NotBefore)
			now = first.Leaf.NotAfter.Add(-lifetime / 3)
			boundary, err := tc.GetCertificate(hello)
			if err != nil {
				t.Fatal(err)
			}
			if boundary != first {
				t.Fatal("renewed a leaf with exactly one-third lifetime remaining")
			}
			now = now.Add(time.Second)
			refreshed, err := tc.GetCertificate(hello)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(first.Certificate[0], refreshed.Certificate[0]) {
				t.Fatal("cached leaf with less than one-third lifetime remaining was not renewed")
			}
			if !refreshed.Leaf.NotAfter.After(first.Leaf.NotAfter) {
				t.Fatal("renewal did not extend the leaf's validity")
			}
		})
	}
}

func TestMintRejectsMalformedRegionLabels(t *testing.T) {
	c := testCA(t)
	tc, _ := c.TLSConfig()
	for _, region := range []string{"random", "test-1", "us-1", "us--east-1", "us-east-one", "us-east-100", "x1-east-1", "us-east-1-extra"} {
		t.Run(region, func(t *testing.T) {
			host := "secretsmanager." + region + ".amazonaws.com"
			if _, err := tc.GetCertificate(&tls.ClientHelloInfo{ServerName: host}); err == nil {
				t.Errorf("minted a certificate for malformed region %q", region)
			}
		})
	}
	if len(c.cache) != 0 {
		t.Fatalf("rejected regions caused %d certificates to be generated", len(c.cache))
	}
}

func TestRejectForeignHosts(t *testing.T) {
	c := testCA(t)
	tc, _ := c.TLSConfig()
	for _, host := range []string{
		"example.com",
		"evil.amazonaws.com",
		"secretsmanager.us-east-1.amazonaws.com.evil.com",
		"notsecretsmanager.us-east-1.amazonaws.com",
		"secretsmanager.us-east-1.amazonaws.com.cn.evil.com",
	} {
		if _, err := tc.GetCertificate(&tls.ClientHelloInfo{ServerName: host}); err == nil {
			t.Fatalf("%s: minted a certificate for a host outside the allowlist", host)
		}
	}
}

func TestNoSNIFallsBackToDefaultRegion(t *testing.T) {
	c := testCA(t)
	tc, _ := c.TLSConfig()
	cert, err := tc.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatalf("no-SNI handshake: %v", err)
	}
	verifyLeaf(t, c, cert, "secretsmanager.us-east-1.amazonaws.com")

	noDefault, err := Ensure(Options{Dir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	noSNI, _ := noDefault.TLSConfig()
	if _, err := noSNI.GetCertificate(&tls.ClientHelloInfo{}); err == nil {
		t.Fatal("no-SNI handshake without a default region should fail")
	}
}

func TestTLSHandshake(t *testing.T) {
	c := testCA(t)
	tc, err := c.TLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})}
	go func() { _ = srv.Serve(tls.NewListener(ln, tc)) }()
	defer srv.Close()

	roots := x509.NewCertPool()
	roots.AddCert(c.Certificate())
	conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
		RootCAs:    roots,
		ServerName: "secretsmanager.us-east-1.amazonaws.com",
		MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("handshake through the minted chain: %v", err)
	}
	_ = conn.Close()
}

func TestMintIsConcurrentSafe(t *testing.T) {
	c := testCA(t)
	tc, _ := c.TLSConfig()
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			host := "secretsmanager.us-east-1.amazonaws.com"
			if i%2 == 0 {
				host = "secretsmanager.eu-west-1.amazonaws.com"
			}
			if _, err := tc.GetCertificate(&tls.ClientHelloInfo{ServerName: host}); err != nil {
				t.Errorf("%s: %v", host, err)
			}
		}(i)
	}
	wg.Wait()
}

func TestConfigCADefaultsAndEnv(t *testing.T) {
	def := config.Default()
	if def.TLS.Mode != "ca" || def.TLS.CADir != "/var/lib/segredium/ca" ||
		def.TLS.CACommonName != DefaultCACommonName || def.TLS.CAValidity != DefaultCAValidity {
		t.Fatalf("tls defaults: %+v", def.TLS)
	}

	cfg, err := config.Load("", func(k string) string {
		switch k {
		case "SEGREDIUM_TLS_CA_DIR":
			return "/srv/segredium/ca"
		case "SEGREDIUM_TLS_CA_COMMON_NAME":
			return "test CA"
		case "SEGREDIUM_TLS_CA_VALIDITY":
			return "48h"
		}
		return ""
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.TLS.CADir != "/srv/segredium/ca" || cfg.TLS.CACommonName != "test CA" ||
		cfg.TLS.CAValidity != 48*time.Hour {
		t.Fatalf("env overrides: %+v", cfg.TLS)
	}
}

func TestConfigCAValidityFromYAML(t *testing.T) {
	p := filepath.Join(t.TempDir(), "segredium.yaml")
	if err := os.WriteFile(p, []byte("tls:\n  ca_dir: /srv/ca\n  ca_validity: 72h\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(p, func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	if cfg.TLS.CADir != "/srv/ca" || cfg.TLS.CAValidity != 72*time.Hour {
		t.Fatalf("yaml: %+v", cfg.TLS)
	}
}

func TestConfigRejectsBadCAValidity(t *testing.T) {
	if _, err := config.Load("", func(k string) string {
		if k == "SEGREDIUM_TLS_CA_VALIDITY" {
			return "forever"
		}
		return ""
	}); err == nil {
		t.Fatal("want error for an invalid ca_validity")
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestEndpointAllowlist(t *testing.T) {
	for _, host := range []string{
		"secretsmanager.us-east-1.amazonaws.com",
		"secretsmanager-fips.us-east-1.amazonaws.com",
		"secretsmanager.us-east-1.api.aws",
		"secretsmanager.cn-north-1.amazonaws.com.cn",
		"secretsmanager.cn-north-1.api.amazonwebservices.com.cn",
		"secretsmanager-fips.cn-north-1.amazonaws.com.cn",
		"secretsmanager.us-gov-west-1.amazonaws.com",
		"secretsmanager.eu-isoe-west-1.amazonaws.com",
	} {
		if !allowedHost(host) {
			t.Errorf("%s should be allowed", host)
		}
	}
	for _, host := range []string{
		"secretsmanager.us-east-1.amazonaws.com.evil.com",
		"secretsmanager.us-east-1.amazonaws.com.cn.evil.com",
		"localhost.evil.com",
		"127.0.0.10",
		"",
		"foo",
	} {
		if allowedHost(host) {
			t.Errorf("%q should be rejected", host)
		}
	}
}
