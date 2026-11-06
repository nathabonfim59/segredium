package cli

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/nathabonfim59/segredium/internal/ca"
	"github.com/nathabonfim59/segredium/internal/config"
)

func init() {
	Register(Command{Name: "ca", Summary: "manage the built-in local CA", Run: caRun})
}

func caRun(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		caUsage(stderr)
		return 2
	}
	switch args[0] {
	case "init":
		return caInit(args[1:], stdout, stderr)
	case "export":
		return caExport(args[1:], stdout, stderr)
	case "install-hint":
		return caInstallHint(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "segredium ca: unknown subcommand %q\n", args[0])
		caUsage(stderr)
		return 2
	}
}

func caUsage(w io.Writer) {
	fmt.Fprint(w, `usage: segredium ca <subcommand> [flags]

subcommands:
  init           create the built-in CA if it does not exist yet
  export         print the CA certificate (PEM) to stdout
  install-hint   print how to trust the CA and route Secrets Manager hostnames here

flags (per subcommand):
  -config PATH   path to the YAML config file (env SEGREDIUM_CONFIG)
  -dir DIR       override tls.ca_dir
`)
}

// caOptions are the flags every ca subcommand shares; the config is loaded exactly like serve.
type caOptions struct {
	configPath string
	dir        string
}

func newCAFlagSet(name string, stderr io.Writer) (*flag.FlagSet, *caOptions) {
	fs := flag.NewFlagSet("ca "+name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	o := &caOptions{}
	fs.StringVar(&o.configPath, "config", os.Getenv("SEGREDIUM_CONFIG"), "path to the YAML config file (env SEGREDIUM_CONFIG)")
	fs.StringVar(&o.dir, "dir", "", "override tls.ca_dir")
	return fs, o
}

func (o *caOptions) load() (*config.Config, error) {
	cfg, err := config.Load(o.configPath, os.Getenv)
	if err != nil {
		return nil, err
	}
	if o.dir != "" {
		cfg.TLS.CADir = o.dir
	}
	return cfg, nil
}

func caFail(stderr io.Writer, cmd string, err error) int {
	fmt.Fprintf(stderr, "segredium %s: %v\n", cmd, err)
	return 1
}

func caInit(args []string, stdout, stderr io.Writer) int {
	fs, o := newCAFlagSet("init", stderr)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, err := o.load()
	if err != nil {
		return caFail(stderr, "ca init", err)
	}
	_, statErr := os.Stat(filepath.Join(cfg.TLS.CADir, ca.CertFileName))
	created := os.IsNotExist(statErr)

	c, err := ca.NewCA(cfg)
	if err != nil {
		return caFail(stderr, "ca init", err)
	}
	status := "already exists"
	if created {
		status = "created"
	}
	fmt.Fprintf(stdout, "CA directory: %s\n%s\ncertificate: %s\n",
		c.Dir(), status, filepath.Join(c.Dir(), ca.CertFileName))
	return 0
}

func caExport(args []string, stdout, stderr io.Writer) int {
	fs, o := newCAFlagSet("export", stderr)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, err := o.load()
	if err != nil {
		return caFail(stderr, "ca export", err)
	}
	c, err := ca.Load(ca.Options{Dir: cfg.TLS.CADir})
	if err != nil {
		if os.IsNotExist(err) {
			return caFail(stderr, "ca export", fmt.Errorf("no CA in %s (run: segredium ca init)", cfg.TLS.CADir))
		}
		return caFail(stderr, "ca export", err)
	}
	if _, err := stdout.Write(c.ExportPEM()); err != nil {
		return caFail(stderr, "ca export", err)
	}
	return 0
}

func caInstallHint(args []string, stdout, stderr io.Writer) int {
	fs, o := newCAFlagSet("install-hint", stderr)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, err := o.load()
	if err != nil {
		return caFail(stderr, "ca install-hint", err)
	}
	certPath := filepath.Join(cfg.TLS.CADir, ca.CertFileName)
	certPath, err = filepath.Abs(certPath)
	if err != nil {
		return caFail(stderr, "ca install-hint", err)
	}
	// The output is pasted into shells, including when ca_dir contains spaces or quotes.
	certPath = "'" + strings.ReplaceAll(certPath, "'", "'\"'\"'") + "'"
	region := cfg.Server.DefaultRegion
	fmt.Fprintf(stdout, `Trust segredium's built-in CA so stock AWS clients accept the redirected endpoints.

1. Route the Secrets Manager endpoints to segredium (/etc/hosts):
   127.0.0.1 secretsmanager.%[2]s.amazonaws.com
   # China partition: 127.0.0.1 secretsmanager.%[2]s.amazonaws.com.cn

2. Trust the CA certificate %[1]s:
   Debian/Ubuntu:
     sudo cp %[1]s /usr/local/share/ca-certificates/segredium.crt
     sudo update-ca-certificates
   RHEL/Fedora/Amazon Linux:
     sudo cp %[1]s /etc/pki/ca-trust/source/anchors/segredium.crt
     sudo update-ca-trust
   macOS:
     sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain %[1]s
   Windows (admin):
     certutil -addstore -f Root %[1]s

3. Tools with their own trust store:
   export AWS_CA_BUNDLE=%[1]s        # AWS CLI v2, boto3, aws-sdk-go-v2
   export SSL_CERT_FILE=%[1]s        # Go's system certificate pool
   export NODE_EXTRA_CA_CERTS=%[1]s  # Node.js
   keytool -importcert -alias segredium -cacerts -file %[1]s  # Java
`, certPath, region)
	return 0
}
