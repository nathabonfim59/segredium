package config

import (
	"fmt"
	"regexp"
)

// ServerConfig: listeners, identity and logging.
type ServerConfig struct {
	// HTTPSAddr is the TLS listener clients reach through /etc/hosts (default ":443"; "" disables).
	HTTPSAddr string `yaml:"https_addr"`
	// HTTPAddr is an optional plain-HTTP listener for AWS_ENDPOINT_URL style use ("" disables).
	HTTPAddr string `yaml:"http_addr"`
	// AccountID is the 12-digit account every ARN is minted for.
	AccountID string `yaml:"account_id"`
	// DefaultRegion is used when neither the SigV4 scope nor the Host header names a region.
	DefaultRegion string `yaml:"default_region"`
	// LogLevel: debug|info|warn|error.
	LogLevel string `yaml:"log_level"`
	// AccessMode: "machine" (default: the machine is the trust boundary, every local caller
	// may access every secret) or "owner" (a secret is accessible only to the Unix user that
	// created it, and to root; callers whose user can't be determined are denied).
	AccessMode string `yaml:"access_mode"`
}

func (s *ServerConfig) defaults() {
	s.HTTPSAddr = ":443"
	s.AccountID = "123456789012"
	s.DefaultRegion = "us-east-1"
	s.LogLevel = "info"
	s.AccessMode = "machine"
}

func (s *ServerConfig) applyEnv(getenv func(string) string) {
	setStr(getenv, "SEGREDIUM_HTTPS_ADDR", &s.HTTPSAddr)
	setStr(getenv, "SEGREDIUM_HTTP_ADDR", &s.HTTPAddr)
	setStr(getenv, "SEGREDIUM_ACCOUNT_ID", &s.AccountID)
	setStr(getenv, "SEGREDIUM_DEFAULT_REGION", &s.DefaultRegion)
	setStr(getenv, "SEGREDIUM_LOG_LEVEL", &s.LogLevel)
	setStr(getenv, "SEGREDIUM_ACCESS_MODE", &s.AccessMode)
}

var accountRe = regexp.MustCompile(`^[0-9]{12}$`)

func (s *ServerConfig) validate() error {
	if !accountRe.MatchString(s.AccountID) {
		return fmt.Errorf("server.account_id must be 12 digits, got %q", s.AccountID)
	}
	if s.HTTPSAddr == "" && s.HTTPAddr == "" {
		return fmt.Errorf("server: at least one of https_addr / http_addr must be set")
	}
	switch s.AccessMode {
	case "machine", "owner":
	default:
		return fmt.Errorf("server.access_mode: want machine or owner, got %q", s.AccessMode)
	}
	switch s.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("server.log_level: unknown level %q", s.LogLevel)
	}
	return nil
}

// setStr overrides *dst with env var name when it is set (even to "": that disables a listener).
func setStr(getenv func(string) string, name string, dst *string) {
	if v, ok := lookup(getenv, name); ok {
		*dst = v
	}
}

// lookup returns name's value. An empty value counts as unset, unless name+"_EMPTY" is "1"
// (e.g. SEGREDIUM_HTTPS_ADDR_EMPTY=1 disables the HTTPS listener).
func lookup(getenv func(string) string, name string) (string, bool) {
	if v := getenv(name); v != "" {
		return v, true
	}
	if getenv(name+"_EMPTY") == "1" {
		return "", true
	}
	return "", false
}
