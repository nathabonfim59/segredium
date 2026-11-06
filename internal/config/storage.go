package config

import (
	"fmt"
	"time"
)

// StorageConfig: persistence and at-rest encryption.
type StorageConfig struct {
	// Backend: "file" (default) or "memory".
	Backend string `yaml:"backend"`
	// Path contains one encrypted file per secret.
	Path string `yaml:"path"`
	// KeyFile defaults to <path>/master.key when empty.
	KeyFile string `yaml:"key_file"`
	// PurgeInterval caps the time between sweeps for expired recovery windows.
	PurgeInterval time.Duration `yaml:"purge_interval"`
}

func (s *StorageConfig) defaults() {
	s.Backend = "file"
	s.Path = "/var/lib/segredium/data"
	s.PurgeInterval = time.Hour
}

func (s *StorageConfig) applyEnv(getenv func(string) string) {
	setStr(getenv, "SEGREDIUM_STORAGE_BACKEND", &s.Backend)
	setStr(getenv, "SEGREDIUM_STORAGE_PATH", &s.Path)
	setStr(getenv, "SEGREDIUM_STORAGE_KEY_FILE", &s.KeyFile)
	if value, ok := lookup(getenv, "SEGREDIUM_STORAGE_PURGE_INTERVAL"); ok {
		interval, err := time.ParseDuration(value)
		if err != nil {
			interval = 0
		}
		s.PurgeInterval = interval
	}
}

func (s *StorageConfig) validate() error {
	if s.PurgeInterval <= 0 {
		return fmt.Errorf("storage.purge_interval must be a positive duration")
	}
	if s.Backend == "" {
		return fmt.Errorf("storage.backend is required")
	}
	if s.Backend == "file" && s.Path == "" {
		return fmt.Errorf("storage.path is required for file storage")
	}
	return nil
}
