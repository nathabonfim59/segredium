// Package config loads segredium's YAML configuration with SEGREDIUM_* env overrides.
//
// Each section lives in its own file: server.go, storage.go, auth.go, tls.go, rotation.go.
// Every section type implements defaults() and applyEnv(); this file only composes them.
package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Server   ServerConfig   `yaml:"server"`
	Storage  StorageConfig  `yaml:"storage"`
	Auth     AuthConfig     `yaml:"auth"`
	TLS      TLSConfig      `yaml:"tls"`
	Rotation RotationConfig `yaml:"rotation"`
}

type section interface {
	defaults()
	applyEnv(getenv func(string) string)
	validate() error
}

func (c *Config) sections() []section {
	return []section{&c.Server, &c.Storage, &c.Auth, &c.TLS, &c.Rotation}
}

// Default returns the configuration with every default applied.
func Default() *Config {
	c := &Config{}
	for _, s := range c.sections() {
		s.defaults()
	}
	return c
}

// Load reads path (optional: "" means defaults only), then applies env overrides, then validates.
func Load(path string, getenv func(string) string) (*Config, error) {
	c := Default()
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("config: %w", err)
		}
		if err := yaml.Unmarshal(b, c); err != nil {
			return nil, fmt.Errorf("config %s: %w", path, err)
		}
	}
	if getenv == nil {
		getenv = os.Getenv
	}
	for _, s := range c.sections() {
		s.applyEnv(getenv)
	}
	for _, s := range c.sections() {
		if err := s.validate(); err != nil {
			return nil, fmt.Errorf("config: %w", err)
		}
	}
	return c, nil
}
