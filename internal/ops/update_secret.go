package ops

import (
	"context"
	"errors"
	"slices"

	"github.com/nathabonfim59/segredium/internal/api"
	"github.com/nathabonfim59/segredium/internal/apierr"
	"github.com/nathabonfim59/segredium/internal/model"
	"github.com/nathabonfim59/segredium/internal/sm"
	"github.com/nathabonfim59/segredium/internal/versions"
)

func init() { api.Register("UpdateSecret", updateSecret) }

type updateSecretInput struct {
	SecretID           *string `json:"SecretId"`
	ClientRequestToken *string `json:"ClientRequestToken"`
	Description        *string `json:"Description"`
	KmsKeyID           *string `json:"KmsKeyId"`
	SecretString       *string `json:"SecretString"`
	SecretBinary       []byte  `json:"SecretBinary"`
	Type               *string `json:"Type"`
}

type updateSecretOutput struct {
	ARN       string `json:"ARN"`
	Name      string `json:"Name"`
	VersionID string `json:"VersionId,omitempty"`
}

func updateSecret(ctx context.Context, d *sm.Deps, r *api.Request) (any, error) {
	var in updateSecretInput
	if err := r.Decode(&in); err != nil {
		return nil, err
	}
	if err := in.validate(); err != nil {
		return nil, err
	}
	s, err := d.Resolve(ctx, r.Region, *in.SecretID)
	if err != nil {
		return nil, err
	}
	if !d.CanAccess(r.Identity.UID, s) {
		return nil, sm.AccessDenied("UpdateSecret")
	}
	hasValue := in.SecretString != nil || in.SecretBinary != nil
	id := ""
	if hasValue {
		id = stringValue(in.ClientRequestToken)
		if id == "" {
			id, err = d.UUID()
			if err != nil {
				return nil, err
			}
		}
	}
	now := d.Now()
	var out *updateSecretOutput
	updated, err := d.Store.UpdateSecret(ctx, r.Region, s.ARN, func(current *model.Secret) error {
		if current.Deleted() {
			return apierr.InvalidRequest(msgDeleted)
		}
		if current.IsReplica {
			return apierr.InvalidRequest("Operation not permitted on a replica secret. Call must be made in primary secret's region.")
		}
		out = &updateSecretOutput{ARN: current.ARN, Name: current.Name, VersionID: id}
		if hasValue {
			if v := current.Version(id); v != nil {
				if !versions.SameValue(v, in.SecretString, in.SecretBinary) {
					return apierr.ResourceExists(msgTokenConflict)
				}
				return errUnchanged
			}
		}
		changed := false
		for _, field := range []struct {
			input  *string
			stored *string
		}{{in.Description, &current.Description}, {in.KmsKeyID, &current.KmsKeyID}, {in.Type, &current.Type}} {
			if field.input != nil && *field.input != *field.stored {
				*field.stored = *field.input
				changed = true
			}
		}
		key := current.KmsKeyID
		if key == "" {
			key = model.DefaultKMSKeyID
		}
		// AWS retains the old keys when re-encrypting current, pending and previous
		// versions; deprecated versions keep their original key metadata.
		// https://docs.aws.amazon.com/secretsmanager/latest/userguide/security-encryption.html
		if in.KmsKeyID != nil {
			for _, v := range current.Versions {
				if v.HasStage(model.StageCurrent) || v.HasStage(model.StagePending) || v.HasStage(model.StagePrevious) {
					if !slices.Contains(v.KmsKeyIDs, key) {
						v.KmsKeyIDs = append(v.KmsKeyIDs, key)
						changed = true
					}
				}
			}
		}
		if hasValue {
			v := &model.Version{VersionID: id, SecretString: in.SecretString, SecretBinary: in.SecretBinary, CreatedDate: now, KmsKeyIDs: []string{key}}
			current.Versions = append(current.Versions, v)
			// API_UpdateSecret: the new value always becomes current, moving the
			// former current version to AWSPREVIOUS through the shared label helper.
			if err := versions.Attach(current, v, []string{model.StageCurrent}); err != nil {
				return err
			}
			if err := versions.Prune(current, now); err != nil {
				return err
			}
			changed = true
		}
		if !changed {
			return errUnchanged
		}
		current.LastChangedDate = &now
		return nil
	})
	if errors.Is(err, errUnchanged) {
		return out, nil
	}
	if err != nil {
		return nil, storeError(err)
	}
	syncReplicas(ctx, d, updated)
	return out, nil
}

func (in *updateSecretInput) validate() error {
	var v sm.Validator
	// Constraints from botocore secretsmanager/2017-10-17/service-2.json.
	v.Required("secretId", in.SecretID != nil)
	v.Length("secretId", in.SecretID, 1, 2048)
	v.Length("clientRequestToken", in.ClientRequestToken, 32, 64)
	v.Length("description", in.Description, 0, 2048)
	v.Length("kmsKeyId", in.KmsKeyID, 0, 2048)
	v.Length("type", in.Type, 0, 256)
	validateValue(&v, in.SecretString, in.SecretBinary)
	if err := v.Err(); err != nil {
		return err
	}
	return valueConflict(in.SecretString, in.SecretBinary, false)
}
