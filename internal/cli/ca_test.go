package cli

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nathabonfim59/segredium/internal/ca"
)

func runCLI(args ...string) (int, string, string) {
	var stdout, stderr bytes.Buffer
	code := Main(args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func parsePEM(t *testing.T, b []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(b)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatal("output is not a CERTIFICATE PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return cert
}

func TestCAInitIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	code, out, errs := runCLI("ca", "init", "-dir", dir)
	if code != 0 {
		t.Fatalf("ca init: code %d, stderr %q", code, errs)
	}
	if !strings.Contains(out, "created") || !strings.Contains(out, dir) {
		t.Fatalf("ca init output = %q", out)
	}
	certPath := filepath.Join(dir, ca.CertFileName)
	stored, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("certificate not written: %v", err)
	}
	parsePEM(t, stored)

	code, out, errs = runCLI("ca", "init", "-dir", dir)
	if code != 0 {
		t.Fatalf("second ca init: code %d, stderr %q", code, errs)
	}
	if !strings.Contains(out, "already exists") {
		t.Fatalf("second ca init output = %q", out)
	}
	if after, err := os.ReadFile(certPath); err != nil || !bytes.Equal(stored, after) {
		t.Fatal("second ca init replaced the CA")
	}
}

func TestCAExport(t *testing.T) {
	dir := t.TempDir()
	if code, _, errs := runCLI("ca", "export", "-dir", dir); code != 1 {
		t.Fatalf("export before init: code %d, want 1 (stderr %q)", code, errs)
	}
	if code, _, errs := runCLI("ca", "init", "-dir", dir); code != 0 {
		t.Fatalf("ca init: %q", errs)
	}
	code, out, errs := runCLI("ca", "export", "-dir", dir)
	if code != 0 {
		t.Fatalf("ca export: code %d, stderr %q", code, errs)
	}
	exported := parsePEM(t, []byte(out))
	stored, err := os.ReadFile(filepath.Join(dir, ca.CertFileName))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(exported.Raw, parsePEM(t, stored).Raw) {
		t.Fatal("exported certificate differs from the stored CA")
	}
}

func TestCAInstallHint(t *testing.T) {
	dir := t.TempDir()
	if code, _, errs := runCLI("ca", "init", "-dir", dir); code != 0 {
		t.Fatalf("ca init: %q", errs)
	}
	code, out, errs := runCLI("ca", "install-hint", "-dir", dir)
	if code != 0 {
		t.Fatalf("ca install-hint: code %d, stderr %q", code, errs)
	}
	certPath := filepath.Join(dir, ca.CertFileName)
	for _, want := range []string{
		certPath,
		"127.0.0.1 secretsmanager.",
		"update-ca-certificates",
		"update-ca-trust",
		"security add-trusted-cert",
		"AWS_CA_BUNDLE=",
		"SSL_CERT_FILE=",
		"NODE_EXTRA_CA_CERTS=",
		"keytool -importcert",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("install-hint missing %q", want)
		}
	}
}

func TestCAUsageAndUnknownSubcommand(t *testing.T) {
	if code, _, errs := runCLI("ca"); code != 2 || !strings.Contains(errs, "usage:") {
		t.Fatalf("bare ca: code %d, stderr %q", code, errs)
	}
	if code, _, errs := runCLI("ca", "bogus"); code != 2 || !strings.Contains(errs, "unknown subcommand") {
		t.Fatalf("bogus subcommand: code %d, stderr %q", code, errs)
	}
	if code, _, _ := runCLI("ca", "init", "-nope"); code != 2 {
		t.Fatal("bad flag should exit 2")
	}
}
