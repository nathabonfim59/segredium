package filestore

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/nathabonfim59/segredium/internal/model"
	"github.com/nathabonfim59/segredium/internal/store"
	"github.com/nathabonfim59/segredium/internal/store/storetest"
)

func openTest(t *testing.T, path string) *Store {
	t.Helper()
	s, err := Open(path, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestConformance(t *testing.T) {
	storetest.Run(t, func(t *testing.T) store.Store { return openTest(t, t.TempDir()) })
}

func TestReopenEncryptedAndCrashLeftover(t *testing.T) {
	ctx := context.Background()
	path := t.TempDir()
	s := openTest(t, path)
	want := storetest.Full("us-east-1", "private-name", 1)
	if err := s.CreateSecret(ctx, want); err != nil {
		t.Fatal(err)
	}
	want.Description = "persisted update"
	if _, err := s.UpdateSecret(ctx, want.Region, want.ARN, func(secret *model.Secret) error { secret.Description = want.Description; return nil }); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(path, filename(want)))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte(want.Name)) || bytes.Contains(data, []byte(want.Description)) {
		t.Fatal("plaintext leaked")
	}
	for _, file := range []string{path, filepath.Join(path, "master.key"), filepath.Join(path, filename(want))} {
		info, err := os.Stat(file)
		if err != nil {
			t.Fatal(err)
		}
		mode := os.FileMode(0600)
		if file == path {
			mode = 0700
		}
		if info.Mode().Perm() != mode {
			t.Fatalf("%s permissions = %o", file, info.Mode().Perm())
		}
	}
	if err := os.WriteFile(filepath.Join(path, ".secret-tmp-interrupted"), []byte("partial ciphertext"), 0600); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s = openTest(t, path)
	got, err := s.GetSecretByARN(ctx, want.Region, want.ARN)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("reopen = %#v, %v", got, err)
	}
	if err := s.DeleteSecret(ctx, want.Region, want.ARN); err != nil {
		t.Fatal(err)
	}
	s = openTest(t, path)
	if _, err := s.GetSecretByARN(ctx, want.Region, want.ARN); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("deleted secret reappeared: %v", err)
	}
}

func TestRefuseCorruptSecretOrKey(t *testing.T) {
	for _, kind := range []string{"ciphertext", "wrong key", "key permissions", "short key"} {
		t.Run(kind, func(t *testing.T) {
			path := t.TempDir()
			s := openTest(t, path)
			secret := storetest.Full("us-east-1", "secret", 1)
			if err := s.CreateSecret(context.Background(), secret); err != nil {
				t.Fatal(err)
			}
			key := filepath.Join(path, "master.key")
			var err error
			switch kind {
			case "ciphertext":
				err = os.WriteFile(filepath.Join(path, filename(secret)), []byte("corrupt"), 0600)
			case "wrong key":
				err = os.WriteFile(key, bytes.Repeat([]byte{1}, 32), 0600)
			case "short key":
				err = os.WriteFile(key, []byte("short"), 0600)
			case "key permissions":
				err = os.Chmod(key, 0640)
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Open(path, ""); err == nil || !strings.Contains(err.Error(), "filestore") {
				t.Fatalf("want clear startup error: %v", err)
			}
		})
	}
}

func TestFailedWriteDoesNotCommit(t *testing.T) {
	ctx := context.Background()
	s := openTest(t, t.TempDir())
	secret := storetest.Full("us-east-1", "a", 1)
	if err := s.CreateSecret(ctx, secret); err != nil {
		t.Fatal(err)
	}
	failure := errors.New("injected disk failure before rename")
	s.write = func(string, []byte) error { return failure }
	if _, err := s.UpdateSecret(ctx, secret.Region, secret.ARN, func(copy *model.Secret) error { copy.Description = "lost"; return nil }); !errors.Is(err, failure) {
		t.Fatalf("update error: %v", err)
	}
	got, err := s.GetSecretByARN(ctx, secret.Region, secret.ARN)
	if err != nil || !reflect.DeepEqual(got, secret) {
		t.Fatalf("failed write changed memory: %v", err)
	}
	other := storetest.Full("us-east-1", "b", 2)
	if err := s.CreateSecret(ctx, other); !errors.Is(err, failure) {
		t.Fatalf("create error: %v", err)
	}
	if _, err := s.GetSecretByARN(ctx, other.Region, other.ARN); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("failed create changed memory: %v", err)
	}
	reopened := openTest(t, s.path)
	got, err = reopened.GetSecretByARN(ctx, secret.Region, secret.ARN)
	if err != nil || !reflect.DeepEqual(got, secret) {
		t.Fatalf("failed write changed disk: %v", err)
	}
}

func TestImmutableChangeNeverReachesDisk(t *testing.T) {
	ctx := context.Background()
	s := openTest(t, t.TempDir())
	secret := storetest.Full("us-east-1", "a", 1)
	if err := s.CreateSecret(ctx, secret); err != nil {
		t.Fatal(err)
	}
	writes := 0
	s.write = func(string, []byte) error { writes++; return nil }
	_, err := s.UpdateSecret(ctx, secret.Region, secret.ARN, func(copy *model.Secret) error { copy.Name = "changed"; return nil })
	if !errors.Is(err, store.ErrImmutable) || writes != 0 {
		t.Fatalf("immutable update error = %v, writes = %d", err, writes)
	}
}

func TestCustomKeyFile(t *testing.T) {
	path := t.TempDir()
	keyPath := filepath.Join(path, "custom.secret")
	s, err := Open(path, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	secret := storetest.Full("us-east-1", "a", 1)
	if err := s.CreateSecret(context.Background(), secret); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s, err = Open(path, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	got, err := s.GetSecretByARN(context.Background(), secret.Region, secret.ARN)
	if err != nil || !reflect.DeepEqual(got, secret) {
		t.Fatalf("custom key reopen: %v", err)
	}
}

func TestRejectOversizedRecord(t *testing.T) {
	path := t.TempDir()
	s := openTest(t, path)
	secret := storetest.Full("us-east-1", "a", 1)
	file, err := os.Create(filepath.Join(path, filename(secret)))
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(maxRecordBytes + 1); err != nil {
		t.Fatal(err)
	}
	file.Close()
	s.Close()
	if _, err := Open(path, ""); err == nil || !strings.Contains(err.Error(), "record limit") {
		t.Fatalf("oversized record: %v", err)
	}
}

func TestWritesOnlyChangedSecret(t *testing.T) {
	ctx := context.Background()
	s := openTest(t, t.TempDir())
	a, b := storetest.Full("us-east-1", "a", 1), storetest.Full("us-east-1", "b", 2)
	for _, secret := range []*model.Secret{a, b} {
		if err := s.CreateSecret(ctx, secret); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(s.path, filename(b))
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpdateSecret(ctx, a.Region, a.ARN, func(secret *model.Secret) error { secret.Description = "changed"; return nil }); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	current, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) || !bytes.Equal(data, current) {
		t.Fatal("updating a rewrote b")
	}
}
