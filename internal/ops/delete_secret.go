package ops

import (
	"context"
	"errors"
	"time"

	"github.com/nathabonfim59/segredium/internal/api"
	"github.com/nathabonfim59/segredium/internal/apierr"
	"github.com/nathabonfim59/segredium/internal/awsjson"
	"github.com/nathabonfim59/segredium/internal/model"
	"github.com/nathabonfim59/segredium/internal/sm"
	"github.com/nathabonfim59/segredium/internal/store"
)

func init() { api.Register("DeleteSecret", deleteSecret) }

type deleteSecretInput struct {
	SecretID                   *string `json:"SecretId"`
	RecoveryWindowInDays       *int64  `json:"RecoveryWindowInDays"`
	ForceDeleteWithoutRecovery *bool   `json:"ForceDeleteWithoutRecovery"`
}

type deleteSecretOutput struct {
	ARN          string        `json:"ARN,omitempty"`
	Name         string        `json:"Name,omitempty"`
	DeletionDate *awsjson.Time `json:"DeletionDate,omitempty"`
}

func deleteSecret(ctx context.Context, d *sm.Deps, r *api.Request) (any, error) {
	var in deleteSecretInput
	if err := r.Decode(&in); err != nil {
		return nil, err
	}
	if err := in.validate(); err != nil {
		return nil, err
	}
	force := in.ForceDeleteWithoutRecovery != nil && *in.ForceDeleteWithoutRecovery
	s, err := d.Resolve(ctx, r.Region, *in.SecretID)
	if err != nil {
		// AWS explicitly allows force deletion of nonexistent secrets. No identity is
		// available to return in that case; the response members are all optional.
		// https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_DeleteSecret.html
		if force && errors.Is(err, apierr.ResourceNotFound("")) {
			return deleteSecretOutput{}, nil
		}
		return nil, err
	}
	if !d.CanAccess(r.Identity.UID, s) {
		return nil, sm.AccessDenied("DeleteSecret")
	}
	if err := deleteSecretReplication(s); err != nil {
		return nil, err
	}
	now := d.Now()
	if force {
		if err := d.Store.DeleteSecret(ctx, r.Region, s.ARN); err != nil && !errors.Is(err, store.ErrNotFound) {
			return nil, storeError(err)
		}
		return deleteSecretOutput{ARN: s.ARN, Name: s.Name, DeletionDate: awsjson.NewTime(now)}, nil
	}
	days := int64(30)
	if in.RecoveryWindowInDays != nil {
		days = *in.RecoveryWindowInDays
	}
	deadline := now.Add(time.Duration(days) * 24 * time.Hour)
	s, err = d.Store.UpdateSecret(ctx, r.Region, s.ARN, func(current *model.Secret) error {
		if !d.CanAccess(r.Identity.UID, current) {
			return sm.AccessDenied("DeleteSecret")
		}
		if err := deleteSecretReplication(current); err != nil {
			return err
		}
		if current.Deleted() {
			return apierr.InvalidRequest(msgDeleted)
		}
		current.DeletedDate, current.DeletionDate = &now, &deadline
		return nil
	})
	if err != nil {
		return nil, storeError(err)
	}
	return deleteSecretOutput{ARN: s.ARN, Name: s.Name, DeletionDate: awsjson.NewTime(deadline)}, nil
}

func deleteSecretReplication(s *model.Secret) error {
	if s.IsReplica {
		return apierr.InvalidRequest("You can't delete a replica secret. Use RemoveRegionsFromReplication in the primary secret's Region to delete this replica.")
	}
	if len(s.Replicas) > 0 {
		return apierr.InvalidRequest("You can't delete a secret that still has replica regions. You must first remove the replica regions using RemoveRegionsFromReplication.")
	}
	return nil
}

func (in *deleteSecretInput) validate() error {
	var v sm.Validator
	v.Required("secretId", in.SecretID != nil)
	v.Length("secretId", in.SecretID, 1, 2048)
	if err := v.Err(); err != nil {
		return err
	}
	// RecoveryWindowInDays has no range trait in service-2.json. These are service
	// errors (InvalidParameterException), rather than model ValidationException.
	if in.RecoveryWindowInDays != nil && in.ForceDeleteWithoutRecovery != nil && *in.ForceDeleteWithoutRecovery {
		return apierr.InvalidParameter("You can't use ForceDeleteWithoutRecovery in conjunction with RecoveryWindowInDays.")
	}
	if in.RecoveryWindowInDays != nil && (*in.RecoveryWindowInDays < 7 || *in.RecoveryWindowInDays > 30) {
		return apierr.InvalidParameter("The RecoveryWindowInDays value must be between 7 and 30 days (inclusive).")
	}
	return nil
}
