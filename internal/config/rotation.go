package config

// RotationConfig: secret rotation.
type RotationConfig struct {
	// Enabled turns the rotation scheduler on.
	Enabled bool `yaml:"enabled"`
}

func (r *RotationConfig) defaults() { r.Enabled = true }

func (r *RotationConfig) applyEnv(getenv func(string) string) {}

func (r *RotationConfig) validate() error { return nil }
