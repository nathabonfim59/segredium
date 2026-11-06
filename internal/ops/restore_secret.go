package ops

import (
	"context"
	"errors"

	"github.com/nathabonfim59/segredium/internal/api"
	"github.com/nathabonfim59/segredium/internal/apierr"
	"github.com/nathabonfim59/segredium/internal/model"
	"github.com/nathabonfim59/segredium/internal/sm"
)

func init() { api.Register("RestoreSecret", restoreSecret) }

type restoreSecretInput struct {
	SecretID *string `json:"SecretId"`
}
type restoreSecretOutput struct {
	ARN  string `json:"ARN"`
	Name string `json:"Name"`
}

func restoreSecret(ctx context.Context, d *sm.Deps, r *api.Request) (any, error) {
	var in restoreSecretInput
	if err := r.Decode(&in); err != nil {
		return nil, err
	}
	var v sm.Validator
	v.Required("secretId", in.SecretID != nil)
	v.Length("secretId", in.SecretID, 1, 2048)
	if err := v.Err(); err != nil {
		return nil, err
	}
	s, err := d.Resolve(ctx, r.Region, *in.SecretID)
	if err != nil {
		return nil, err
	}
	if !d.CanAccess(r.Identity.UID, s) {
		return nil, sm.AccessDenied("RestoreSecret")
	}
	_, err = d.Store.UpdateSecret(ctx, r.Region, s.ARN, func(current *model.Secret) error {
		if !d.CanAccess(r.Identity.UID, current) {
			return sm.AccessDenied("RestoreSecret")
		}
		// AWS permits recovery only before DeletionDate, even if background purge
		// has not yet removed the record. Checking under the update lock also
		// prevents a successful restore from racing a due purge.
		// https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_DeleteSecret.html
		if current.DeletionDate != nil && !current.DeletionDate.After(d.Now()) {
			return apierr.InvalidRequest("You can't restore this secret because the recovery window has expired.")
		}
		if current.DeletedDate == nil && current.DeletionDate == nil {
			return errUnchanged
		}
		current.DeletedDate, current.DeletionDate = nil, nil
		return nil
	})
	if err != nil && !errors.Is(err, errUnchanged) {
		return nil, storeError(err)
	}
	return restoreSecretOutput{ARN: s.ARN, Name: s.Name}, nil
}
