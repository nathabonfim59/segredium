// Package store defines the persistence contract. Every backend must pass
// storetest.Run.
//
// Semantics every backend guarantees:
//   - Secrets are partitioned by Region. ARN is globally unique. Name is unique within a region
//     among all secrets the store holds (including ones scheduled for deletion: the service layer
//     decides what a deleted secret means; only DeleteSecret frees the name).
//   - Returned secrets are deep copies; mutating them never changes stored state.
//   - UpdateSecret is atomic: fn runs on a copy while no other write to that secret can interleave;
//     if fn returns an error nothing is stored and that error is returned unchanged.
//     fn must not change ARN, Name or Region (ErrImmutable).
//   - ListSecrets returns every secret in the region ordered by CreatedDate ascending, ties
//     broken by ARN ascending.
package store

import (
	"context"
	"errors"

	"github.com/nathabonfim59/segredium/internal/model"
)

var (
	ErrNotFound  = errors.New("store: secret not found")
	ErrExists    = errors.New("store: secret name already exists in region")
	ErrImmutable = errors.New("store: ARN, Name and Region are immutable")
)

type Store interface {
	// CreateSecret stores a new secret. ErrExists if Region+Name or ARN is taken.
	CreateSecret(ctx context.Context, s *model.Secret) error
	// GetSecretByARN returns the secret with that exact ARN in region, or ErrNotFound.
	GetSecretByARN(ctx context.Context, region, arn string) (*model.Secret, error)
	// GetSecretByName returns the secret named name in region, or ErrNotFound.
	GetSecretByName(ctx context.Context, region, name string) (*model.Secret, error)
	// ListSecrets returns all secrets in region (see ordering above).
	ListSecrets(ctx context.Context, region string) ([]*model.Secret, error)
	// ListRegions returns every region that holds at least one secret, sorted.
	ListRegions(ctx context.Context) ([]string, error)
	// UpdateSecret atomically applies fn and returns the stored result.
	UpdateSecret(ctx context.Context, region, arn string, fn func(*model.Secret) error) (*model.Secret, error)
	// DeleteSecret permanently removes a secret (and frees its name). ErrNotFound if absent.
	DeleteSecret(ctx context.Context, region, arn string) error
	Close() error
}

// MetaLister is an optional Store extension for low-memory listing. ListSecretsMeta returns
// the same secrets, in the same order, as ListSecrets, but every Version has SecretString and
// SecretBinary nil (ids, stages, dates and KMS ids kept), so listing never copies secret
// values. Use store.ListMeta, which falls back to ListSecrets for stores without it.
type MetaLister interface {
	ListSecretsMeta(ctx context.Context, region string) ([]*model.Secret, error)
}

// ListMeta lists region's secrets without copying secret values when s supports it.
func ListMeta(ctx context.Context, s Store, region string) ([]*model.Secret, error) {
	if ml, ok := s.(MetaLister); ok {
		return ml.ListSecretsMeta(ctx, region)
	}
	return s.ListSecrets(ctx, region)
}
