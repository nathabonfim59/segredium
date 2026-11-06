package config

import "fmt"

// AuthConfig: request authentication.
type AuthConfig struct {
	// Mode: "none" (accept any or no signature; region still read from the SigV4 scope) or
	// "verify" (not implemented yet).
	Mode string `yaml:"mode"`
}

func (a *AuthConfig) defaults() { a.Mode = "none" }

func (a *AuthConfig) applyEnv(getenv func(string) string) {
	setStr(getenv, "SEGREDIUM_AUTH_MODE", &a.Mode)
}

func (a *AuthConfig) validate() error {
	if a.Mode == "" {
		return fmt.Errorf("auth.mode is required")
	}
	return nil
}
