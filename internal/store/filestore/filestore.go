// Package filestore keeps an in-memory index backed by one encrypted file per secret.
package filestore

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/nathabonfim59/segredium/internal/model"
	"github.com/nathabonfim59/segredium/internal/store"
	"github.com/nathabonfim59/segredium/internal/store/memstore"
)

type Store struct {
	// Readers wait until a durable write has also committed to the index.
	mu    sync.RWMutex
	index *memstore.Store
	path  string
	aead  cipher.AEAD
	// Kept on the instance so tests can fail writes without global hooks.
	write func(string, []byte) error
}

// 100 versions of 64 KiB each fit even with JSON's worst-case six-byte escaping.
// Bound startup reads so a corrupt oversized file cannot exhaust memory.
const maxRecordBytes = 64 << 20

func Open(path, keyFile string) (*Store, error) {
	if err := os.MkdirAll(path, 0700); err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0700); err != nil {
		return nil, err
	}
	if keyFile == "" {
		keyFile = filepath.Join(path, "master.key")
	}
	keyPath, err := filepath.Abs(keyFile)
	if err != nil {
		return nil, err
	}
	key, err := masterKey(keyFile)
	if err != nil {
		return nil, fmt.Errorf("filestore master key: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	s := &Store{index: memstore.New(), path: path, aead: aead}
	s.write = s.atomicWrite
	dir, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	for {
		entries, err := dir.ReadDir(64)
		if err != nil && err != io.EOF {
			return nil, err
		}
		for _, entry := range entries {
			name := entry.Name()
			entryPath, err := filepath.Abs(filepath.Join(path, name))
			if err != nil {
				return nil, err
			}
			if entryPath == keyPath {
				continue
			}
			if strings.HasPrefix(name, ".secret-tmp-") {
				continue
			}
			if !strings.HasSuffix(name, ".secret") {
				continue
			}
			if !entry.Type().IsRegular() {
				return nil, fmt.Errorf("filestore: %s is not a regular secret file", name)
			}
			if err := s.load(name); err != nil {
				return nil, fmt.Errorf("filestore: cannot load %s: %w", name, err)
			}
		}
		if err == io.EOF {
			break
		}
	}
	return s, nil
}

func masterKey(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, err
		}
		// Link publishes the fully synced key without overwriting a concurrent creator.
		var tmp *os.File
		tmp, err = os.CreateTemp(filepath.Dir(path), ".master-key-*")
		if err != nil {
			return nil, err
		}
		defer os.Remove(tmp.Name())
		_, err = tmp.Write(key)
		if err == nil {
			err = tmp.Sync()
		}
		closeErr := tmp.Close()
		if err != nil {
			return nil, err
		}
		if closeErr != nil {
			return nil, closeErr
		}
		if err = os.Link(tmp.Name(), path); err != nil && !errors.Is(err, os.ErrExist) {
			return nil, err
		}
		if err = syncDir(filepath.Dir(path)); err != nil {
			return nil, err
		}
		info, err = os.Lstat(path)
	}
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return nil, fmt.Errorf("%s must be a regular file accessible only to its owner (0600)", path)
	}
	// Limit the read even if an invalid key file is very large.
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	key, err := io.ReadAll(io.LimitReader(f, 33))
	if err != nil {
		return nil, err
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("%s must contain exactly 32 bytes", path)
	}
	return key, nil
}

func filename(s *model.Secret) string {
	hash := sha256.Sum256([]byte(s.Region + "\x00" + s.ARN))
	return hex.EncodeToString(hash[:]) + ".secret"
}

func (s *Store) load(name string) error {
	f, err := os.Open(filepath.Join(s.path, name))
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if info.Size() > maxRecordBytes {
		return errors.New("encrypted secret exceeds 64 MiB record limit")
	}
	data, err := io.ReadAll(io.LimitReader(f, maxRecordBytes+1))
	if err != nil {
		return err
	}
	if len(data) > maxRecordBytes {
		return errors.New("encrypted secret exceeds 64 MiB record limit")
	}
	n := s.aead.NonceSize()
	if len(data) < n {
		return errors.New("truncated encrypted secret")
	}
	// Decrypt in place to avoid holding a second whole encrypted record during startup.
	plain, err := s.aead.Open(data[n:n], data[:n], data[n:], []byte(name))
	if err != nil {
		return fmt.Errorf("decrypt secret: %w", err)
	}
	var secret model.Secret
	if err := json.Unmarshal(plain, &secret); err != nil {
		return err
	}
	if filename(&secret) != name {
		return errors.New("secret identity does not match file name")
	}
	return s.index.CreateSecret(context.Background(), &secret)
}

func (s *Store) persist(secret *model.Secret) error {
	plain, err := json.Marshal(secret)
	if err != nil {
		return err
	}
	if len(plain)+s.aead.NonceSize()+s.aead.Overhead() > maxRecordBytes {
		return errors.New("encrypted secret exceeds 64 MiB record limit")
	}
	nonce := make([]byte, s.aead.NonceSize(), s.aead.NonceSize()+len(plain)+s.aead.Overhead())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	name := filename(secret)
	return s.write(name, s.aead.Seal(nonce, nonce, plain, []byte(name)))
}

func (s *Store) atomicWrite(name string, data []byte) error {
	f, err := os.CreateTemp(s.path, ".secret-tmp-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err := os.Rename(f.Name(), filepath.Join(s.path, name)); err != nil {
		return err
	}
	return syncDir(s.path)
}

func syncDir(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

func (s *Store) CreateSecret(ctx context.Context, secret *model.Secret) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	// ARN uniqueness also applies across regions.
	regions, err := s.index.ListRegions(ctx)
	if err != nil {
		return err
	}
	for _, region := range regions {
		if _, err := s.index.GetSecretByARN(ctx, region, secret.ARN); err == nil {
			return store.ErrExists
		} else if !errors.Is(err, store.ErrNotFound) {
			return err
		}
	}
	if _, err := s.index.GetSecretByName(ctx, secret.Region, secret.Name); err == nil {
		return store.ErrExists
	} else if !errors.Is(err, store.ErrNotFound) {
		return err
	}
	copy := secret.Clone()
	if err := s.persist(copy); err != nil {
		return err
	}
	// The write is committed; cancellation must not leave the index behind disk.
	return s.index.CreateSecret(context.Background(), copy)
}

func (s *Store) UpdateSecret(ctx context.Context, region, arn string, fn func(*model.Secret) error) (*model.Secret, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, err := s.index.GetSecretByARN(ctx, region, arn)
	if err != nil {
		return nil, err
	}
	// GetSecretByARN already returned a detached copy; keep only its immutable identity.
	originalARN, originalName, originalRegion := cur.ARN, cur.Name, cur.Region
	copy := cur
	if err := fn(copy); err != nil {
		return nil, err
	}
	if copy.ARN != originalARN || copy.Name != originalName || copy.Region != originalRegion {
		return nil, store.ErrImmutable
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := s.persist(copy); err != nil {
		return nil, err
	}
	return s.index.UpdateSecret(context.Background(), region, arn, func(current *model.Secret) error { *current = *copy; return nil })
}

func (s *Store) DeleteSecret(ctx context.Context, region, arn string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	secret, err := s.index.GetSecretByARN(ctx, region, arn)
	if err != nil {
		return err
	}
	if err := os.Remove(filepath.Join(s.path, filename(secret))); err != nil {
		return err
	}
	if err := syncDir(s.path); err != nil {
		return err
	}
	return s.index.DeleteSecret(context.Background(), region, arn)
}

func (s *Store) GetSecretByARN(ctx context.Context, region, arn string) (*model.Secret, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.index.GetSecretByARN(ctx, region, arn)
}

func (s *Store) GetSecretByName(ctx context.Context, region, name string) (*model.Secret, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.index.GetSecretByName(ctx, region, name)
}

func (s *Store) ListSecrets(ctx context.Context, region string) ([]*model.Secret, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.index.ListSecrets(ctx, region)
}

func (s *Store) ListRegions(ctx context.Context) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.index.ListRegions(ctx)
}

func (s *Store) ListSecretsMeta(ctx context.Context, region string) ([]*model.Secret, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.index.ListSecretsMeta(ctx, region)
}

func (s *Store) Close() error { return nil }

var _ store.Store = (*Store)(nil)
