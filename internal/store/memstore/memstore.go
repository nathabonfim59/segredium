// Package memstore is the in-memory reference implementation of store.Store.
package memstore

import (
	"cmp"
	"context"
	"slices"
	"sync"

	"github.com/nathabonfim59/segredium/internal/model"
	"github.com/nathabonfim59/segredium/internal/store"
)

type Store struct {
	mu      sync.Mutex
	byARN   map[string]*model.Secret // arn -> secret
	byName  map[string]string        // region+"\x00"+name -> arn
	regions map[string]int           // region -> count
}

func New() *Store {
	return &Store{byARN: map[string]*model.Secret{}, byName: map[string]string{}, regions: map[string]int{}}
}

func key(region, name string) string { return region + "\x00" + name }

func (m *Store) CreateSecret(ctx context.Context, s *model.Secret) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.byARN[s.ARN]; ok {
		return store.ErrExists
	}
	k := key(s.Region, s.Name)
	if _, ok := m.byName[k]; ok {
		return store.ErrExists
	}
	m.byARN[s.ARN] = s.Clone()
	m.byName[k] = s.ARN
	m.regions[s.Region]++
	return nil
}

func (m *Store) GetSecretByARN(ctx context.Context, region, arn string) (*model.Secret, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.byARN[arn]
	if !ok || s.Region != region {
		return nil, store.ErrNotFound
	}
	return s.Clone(), nil
}

func (m *Store) GetSecretByName(ctx context.Context, region, name string) (*model.Secret, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	arn, ok := m.byName[key(region, name)]
	if !ok {
		return nil, store.ErrNotFound
	}
	return m.byARN[arn].Clone(), nil
}

func (m *Store) ListSecrets(ctx context.Context, region string) ([]*model.Secret, error) {
	return m.list(ctx, region, (*model.Secret).Clone)
}

func (m *Store) list(ctx context.Context, region string, clone func(*model.Secret) *model.Secret) ([]*model.Secret, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	var out []*model.Secret
	for _, s := range m.byARN {
		if s.Region == region {
			out = append(out, clone(s))
		}
	}
	m.mu.Unlock()
	slices.SortFunc(out, func(a, b *model.Secret) int {
		if c := a.CreatedDate.Compare(b.CreatedDate); c != 0 {
			return c
		}
		return cmp.Compare(a.ARN, b.ARN)
	})
	return out, nil
}

// ListSecretsMeta implements store.MetaLister: like ListSecrets, without secret values.
func (m *Store) ListSecretsMeta(ctx context.Context, region string) ([]*model.Secret, error) {
	return m.list(ctx, region, (*model.Secret).CloneMeta)
}

func (m *Store) ListRegions(ctx context.Context) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, 0, len(m.regions))
	for r, n := range m.regions {
		if n > 0 {
			out = append(out, r)
		}
	}
	slices.Sort(out)
	return out, nil
}

func (m *Store) UpdateSecret(ctx context.Context, region, arn string, fn func(*model.Secret) error) (*model.Secret, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	cur, ok := m.byARN[arn]
	if !ok || cur.Region != region {
		return nil, store.ErrNotFound
	}
	c := cur.Clone()
	if err := fn(c); err != nil {
		return nil, err
	}
	if c.ARN != cur.ARN || c.Name != cur.Name || c.Region != cur.Region {
		return nil, store.ErrImmutable
	}
	m.byARN[arn] = c.Clone()
	return c, nil
}

func (m *Store) DeleteSecret(ctx context.Context, region, arn string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.byARN[arn]
	if !ok || s.Region != region {
		return store.ErrNotFound
	}
	delete(m.byARN, arn)
	delete(m.byName, key(s.Region, s.Name))
	m.regions[s.Region]--
	if m.regions[s.Region] <= 0 {
		delete(m.regions, s.Region)
	}
	return nil
}

func (m *Store) Close() error { return nil }

var _ store.Store = (*Store)(nil)
