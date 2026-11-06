package config

import (
	"os"
	"path/filepath"
	"testing"
)

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestDefaultsValidate(t *testing.T) {
	c, err := Load("", env(nil))
	if err != nil {
		t.Fatal(err)
	}
	if c.Server.HTTPSAddr != ":443" || c.Server.DefaultRegion != "us-east-1" || c.Storage.Backend != "file" || c.Storage.Path != "/var/lib/segredium/data" {
		t.Fatalf("defaults: %+v", c)
	}
}

func TestFileThenEnv(t *testing.T) {
	p := filepath.Join(t.TempDir(), "c.yaml")
	if err := os.WriteFile(p, []byte("server:\n  account_id: \"111122223333\"\n  http_addr: \":8080\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(p, env(map[string]string{"SEGREDIUM_DEFAULT_REGION": "eu-west-1", "SEGREDIUM_HTTPS_ADDR_EMPTY": "1"}))
	if err != nil {
		t.Fatal(err)
	}
	if c.Server.AccountID != "111122223333" || c.Server.HTTPAddr != ":8080" || c.Server.DefaultRegion != "eu-west-1" || c.Server.HTTPSAddr != "" {
		t.Fatalf("got %+v", c.Server)
	}
}

func TestInvalid(t *testing.T) {
	if _, err := Load("", env(map[string]string{"SEGREDIUM_ACCOUNT_ID": "12"})); err == nil {
		t.Fatal("want error for bad account id")
	}
}

func TestStorageConfiguration(t *testing.T) {
	for _, backend := range []string{"file", "memory"} {
		c, err := Load("", env(map[string]string{
			"SEGREDIUM_STORAGE_BACKEND":  backend,
			"SEGREDIUM_STORAGE_PATH":     "/custom/data",
			"SEGREDIUM_STORAGE_KEY_FILE": "/custom/master.key",
		}))
		if err != nil {
			t.Fatal(err)
		}
		if c.Storage.Backend != backend || c.Storage.Path != "/custom/data" || c.Storage.KeyFile != "/custom/master.key" {
			t.Fatalf("storage overrides: %+v", c.Storage)
		}
	}
	if _, err := Load("", env(map[string]string{"SEGREDIUM_STORAGE_PATH_EMPTY": "1"})); err == nil {
		t.Fatal("file backend accepted empty path")
	}
}
