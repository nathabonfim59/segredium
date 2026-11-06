package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestStoragePurgeInterval(t *testing.T) {
	if Default().Storage.PurgeInterval != time.Hour {
		t.Fatal("purge interval must default to one hour")
	}
	p := filepath.Join(t.TempDir(), "storage.yaml")
	if err := os.WriteFile(p, []byte("storage:\n  purge_interval: 15m\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		value string
		want  time.Duration
	}{{"", 15 * time.Minute}, {"30s", 30 * time.Second}} {
		c, err := Load(p, env(map[string]string{"SEGREDIUM_STORAGE_PURGE_INTERVAL": tc.value}))
		if err != nil || c.Storage.PurgeInterval != tc.want {
			t.Fatalf("interval %q: config=%+v err=%v", tc.value, c, err)
		}
	}
	for _, value := range []string{"0", "-1s", "bad", "999999999999999999999h"} {
		if _, err := Load("", env(map[string]string{"SEGREDIUM_STORAGE_PURGE_INTERVAL": value})); err == nil || !strings.Contains(err.Error(), "storage.purge_interval") {
			t.Fatalf("interval %q: %v", value, err)
		}
	}
	if err := os.WriteFile(p, []byte("storage:\n  purge_interval: 0s\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p, env(nil)); err == nil {
		t.Fatal("zero YAML interval accepted")
	}
}
