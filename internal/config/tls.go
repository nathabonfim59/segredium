package config

import (
	"fmt"
	"time"

	"gopkg.in/yaml.v3"
)

// TLSConfig: the HTTPS listener's certificates.
type TLSConfig struct {
	// Mode: "files" (CertFile/KeyFile) or "ca" (built-in CA).
	Mode     string `yaml:"mode"`
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`

	// CADir holds the built-in CA's root certificate (ca.crt.pem) and key (ca.key.pem).
	CADir string `yaml:"ca_dir"`
	// CACommonName is the root certificate's subject CN.
	CACommonName string `yaml:"ca_common_name"`
	// CAValidity is the root certificate's lifetime (YAML accepts "87600h" or nanoseconds).
	CAValidity time.Duration `yaml:"ca_validity"`

	// caValidityErr records a bad SEGREDIUM_TLS_CA_VALIDITY for validate() to report.
	caValidityErr error
}

func (t *TLSConfig) defaults() {
	t.Mode = "ca"
	t.CADir = "/var/lib/segredium/ca"
	t.CACommonName = "segredium local CA"
	t.CAValidity = 10 * 365 * 24 * time.Hour
	t.caValidityErr = nil
}

func (t *TLSConfig) applyEnv(getenv func(string) string) {
	setStr(getenv, "SEGREDIUM_TLS_MODE", &t.Mode)
	setStr(getenv, "SEGREDIUM_TLS_CERT_FILE", &t.CertFile)
	setStr(getenv, "SEGREDIUM_TLS_KEY_FILE", &t.KeyFile)
	setStr(getenv, "SEGREDIUM_TLS_CA_DIR", &t.CADir)
	setStr(getenv, "SEGREDIUM_TLS_CA_COMMON_NAME", &t.CACommonName)
	if v, ok := lookup(getenv, "SEGREDIUM_TLS_CA_VALIDITY"); ok {
		d, err := time.ParseDuration(v)
		if err != nil {
			t.caValidityErr = fmt.Errorf("tls.ca_validity: %w", err)
		} else {
			t.CAValidity = d
		}
	}
}

func (t *TLSConfig) validate() error {
	if t.caValidityErr != nil {
		return t.caValidityErr
	}
	switch t.Mode {
	case "files":
		if t.CertFile == "" || t.KeyFile == "" {
			return fmt.Errorf("tls.mode=files needs tls.cert_file and tls.key_file")
		}
	case "ca":
		if t.CADir == "" {
			return fmt.Errorf("tls.mode=ca needs tls.ca_dir")
		}
		if t.CACommonName == "" {
			return fmt.Errorf("tls.mode=ca needs tls.ca_common_name")
		}
		if t.CAValidity <= 0 {
			return fmt.Errorf("tls.mode=ca needs a positive tls.ca_validity")
		}
	default:
		return fmt.Errorf("tls.mode: unknown mode %q (want files or ca)", t.Mode)
	}
	return nil
}

// UnmarshalYAML lets ca_validity be a duration string ("87600h") as well as a raw nanosecond
// count, while leaving fields absent from the file at their defaults.
func (t *TLSConfig) UnmarshalYAML(value *yaml.Node) error {
	var raw struct {
		Mode         *string        `yaml:"mode"`
		CertFile     *string        `yaml:"cert_file"`
		KeyFile      *string        `yaml:"key_file"`
		CADir        *string        `yaml:"ca_dir"`
		CACommonName *string        `yaml:"ca_common_name"`
		CAValidity   *durationValue `yaml:"ca_validity"`
	}
	if err := value.Decode(&raw); err != nil {
		return err
	}
	if raw.Mode != nil {
		t.Mode = *raw.Mode
	}
	if raw.CertFile != nil {
		t.CertFile = *raw.CertFile
	}
	if raw.KeyFile != nil {
		t.KeyFile = *raw.KeyFile
	}
	if raw.CADir != nil {
		t.CADir = *raw.CADir
	}
	if raw.CACommonName != nil {
		t.CACommonName = *raw.CACommonName
	}
	if raw.CAValidity != nil {
		t.CAValidity = time.Duration(*raw.CAValidity)
	}
	return nil
}

// durationValue decodes either a Go duration string or an integer nanosecond count.
type durationValue time.Duration

func (d *durationValue) UnmarshalYAML(value *yaml.Node) error {
	if value.Tag == "!!str" {
		parsed, err := time.ParseDuration(value.Value)
		if err != nil {
			return fmt.Errorf("invalid duration %q: %w", value.Value, err)
		}
		*d = durationValue(parsed)
		return nil
	}
	var n int64
	if err := value.Decode(&n); err != nil {
		return err
	}
	*d = durationValue(n)
	return nil
}
