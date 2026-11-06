package ops

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"

	"github.com/nathabonfim59/segredium/internal/api"
	"github.com/nathabonfim59/segredium/internal/apierr"
	"github.com/nathabonfim59/segredium/internal/model"
	"github.com/nathabonfim59/segredium/internal/sm"
	"github.com/nathabonfim59/segredium/internal/versions"
)

func init() { api.Register("PutSecretValue", putSecretValue) }

type putSecretValueInput struct {
	SecretID           *string   `json:"SecretId"`
	ClientRequestToken *string   `json:"ClientRequestToken"`
	SecretString       *string   `json:"SecretString"`
	SecretBinary       []byte    `json:"SecretBinary"`
	VersionStages      []*string `json:"VersionStages"`
	RotationToken      *string   `json:"RotationToken"`
}

type putSecretValueOutput struct {
	ARN           string   `json:"ARN"`
	Name          string   `json:"Name"`
	VersionID     string   `json:"VersionId"`
	VersionStages []string `json:"VersionStages,omitempty"`
}

var rotationTokenPattern = regexp.MustCompile(`^[a-zA-Z0-9\-]+$`)

func putSecretValue(ctx context.Context, d *sm.Deps, r *api.Request) (any, error) {
	var in putSecretValueInput
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
		return nil, sm.AccessDenied("PutSecretValue")
	}
	id := stringValue(in.ClientRequestToken)
	if id == "" {
		// The model's idempotencyToken is optional. Generate it for raw HTTP clients
		// that do not inject a token as AWS SDKs do, preserving drop-in compatibility.
		id, err = d.UUID()
		if err != nil {
			return nil, err
		}
	}
	now := d.Now()
	var out *putSecretValueOutput
	updated, err := d.Store.UpdateSecret(ctx, r.Region, s.ARN, func(current *model.Secret) error {
		if current.Deleted() {
			return apierr.InvalidRequest(msgDeleted)
		}
		if current.IsReplica {
			return apierr.InvalidRequest("Operation not permitted on a replica secret. Call must be made in primary secret's region.")
		}
		if v := current.Version(id); v != nil {
			if !versions.SameValue(v, in.SecretString, in.SecretBinary) {
				return apierr.ResourceExists(msgTokenConflict)
			}
			out = &putSecretValueOutput{ARN: current.ARN, Name: current.Name, VersionID: id, VersionStages: v.Stages}
			return errUnchanged
		}
		var stages []string
		for _, stage := range in.VersionStages {
			if !slices.Contains(stages, *stage) {
				stages = append(stages, *stage)
			}
		}
		// The first value always gets AWSCURRENT even with explicit custom labels.
		// https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_PutSecretValue.html
		if in.VersionStages == nil || len(current.Versions) == 0 && !slices.Contains(stages, model.StageCurrent) {
			stages = append(stages, model.StageCurrent)
		}
		key := current.KmsKeyID
		if key == "" {
			key = model.DefaultKMSKeyID
		}
		v := &model.Version{VersionID: id, SecretString: in.SecretString, SecretBinary: in.SecretBinary, CreatedDate: now, KmsKeyIDs: []string{key}}
		current.Versions = append(current.Versions, v)
		if err := versions.Attach(current, v, stages); err != nil {
			return err
		}
		if err := versions.Prune(current, now); err != nil {
			return err
		}
		current.LastChangedDate = &now
		out = &putSecretValueOutput{ARN: current.ARN, Name: current.Name, VersionID: id, VersionStages: v.Stages}
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

func (in *putSecretValueInput) validate() error {
	var v sm.Validator
	v.Required("secretId", in.SecretID != nil)
	v.Length("secretId", in.SecretID, 1, 2048)
	v.Length("clientRequestToken", in.ClientRequestToken, 32, 64)
	validateValue(&v, in.SecretString, in.SecretBinary)
	v.SensitiveLength("rotationToken", in.RotationToken, 36, 256)
	// RotationToken is sensitive in service-2.json, including on constraint failures.
	if in.RotationToken != nil && !rotationTokenPattern.MatchString(*in.RotationToken) {
		v.Custom("Value at 'rotationToken' failed to satisfy constraint: Member must satisfy regular expression pattern: " + rotationTokenPattern.String())
	}
	if in.VersionStages != nil {
		if len(in.VersionStages) < 1 {
			v.Custom("Value '[]' at 'versionStages' failed to satisfy constraint: Member must have length greater than or equal to 1")
		}
		if len(in.VersionStages) > 20 {
			v.Custom(fmt.Sprintf("Value at 'versionStages' failed to satisfy constraint: Member must have length less than or equal to %d", 20))
		}
		for i, stage := range in.VersionStages {
			member := fmt.Sprintf("versionStages.%d.member", i+1)
			v.Required(member, stage != nil)
			v.Length(member, stage, 1, 256)
		}
	}
	if err := v.Err(); err != nil {
		return err
	}
	return valueConflict(in.SecretString, in.SecretBinary, true)
}
