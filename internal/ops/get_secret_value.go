package ops

import (
	"context"
	"errors"

	"github.com/nathabonfim59/segredium/internal/api"
	"github.com/nathabonfim59/segredium/internal/apierr"
	"github.com/nathabonfim59/segredium/internal/awsjson"
	"github.com/nathabonfim59/segredium/internal/model"
	"github.com/nathabonfim59/segredium/internal/sm"
)

func init() { api.Register("GetSecretValue", getSecretValue) }

type getSecretValueInput struct {
	SecretID     *string `json:"SecretId"`
	VersionID    *string `json:"VersionId"`
	VersionStage *string `json:"VersionStage"`
}

type getSecretValueOutput struct {
	ARN           string        `json:"ARN"`
	Name          string        `json:"Name"`
	VersionID     string        `json:"VersionId"`
	SecretBinary  []byte        `json:"SecretBinary,omitempty"`
	SecretString  *string       `json:"SecretString,omitempty"`
	VersionStages []string      `json:"VersionStages,omitempty"`
	CreatedDate   *awsjson.Time `json:"CreatedDate,omitempty"`
}

func getSecretValue(ctx context.Context, d *sm.Deps, r *api.Request) (any, error) {
	var in getSecretValueInput
	if err := r.Decode(&in); err != nil {
		return nil, err
	}
	var validator sm.Validator
	validator.Required("secretId", in.SecretID != nil)
	validator.Length("secretId", in.SecretID, 1, 2048)
	validator.Length("versionId", in.VersionID, 32, 64)
	validator.Length("versionStage", in.VersionStage, 1, 256)
	if err := validator.Err(); err != nil {
		return nil, err
	}
	s, err := d.Resolve(ctx, r.Region, *in.SecretID)
	if err != nil {
		return nil, err
	}
	if !d.CanAccess(r.Identity.UID, s) {
		return nil, sm.AccessDenied("GetSecretValue")
	}
	v, err := in.selectVersion(s)
	if err != nil {
		return nil, err
	}
	day := model.Day(d.Now())
	// Reads on an already accessed day need only Resolve's required store clone.
	if s.LastAccessedDate == nil || !s.LastAccessedDate.Equal(day) || v.LastAccessedDate == nil || !v.LastAccessedDate.Equal(day) {
		_, err = d.Store.UpdateSecret(ctx, r.Region, s.ARN, func(current *model.Secret) error {
			selected, err := in.selectVersion(current)
			if err != nil {
				return err
			}
			s, v = current, selected
			if current.LastAccessedDate != nil && current.LastAccessedDate.Equal(day) && selected.LastAccessedDate != nil && selected.LastAccessedDate.Equal(day) {
				return errUnchanged
			}
			current.LastAccessedDate = &day
			selected.LastAccessedDate = &day
			return nil
		})
		if err != nil && !errors.Is(err, errUnchanged) {
			return nil, storeError(err)
		}
	}
	return &getSecretValueOutput{ARN: s.ARN, Name: s.Name, VersionID: v.VersionID, SecretBinary: v.SecretBinary, SecretString: v.SecretString, VersionStages: v.Stages, CreatedDate: awsjson.NewTime(v.CreatedDate)}, nil
}

func (in *getSecretValueInput) selectVersion(s *model.Secret) (*model.Version, error) {
	if s.Deleted() {
		return nil, apierr.InvalidRequest(msgDeleted)
	}
	if in.VersionID != nil {
		v := s.Version(*in.VersionID)
		if v == nil {
			return nil, apierr.ResourceNotFound("Secrets Manager can't find the specified secret value for VersionId: %s", *in.VersionID)
		}
		if in.VersionStage != nil && !v.HasStage(*in.VersionStage) {
			return nil, apierr.InvalidRequest("You provided a VersionStage that is not associated to the provided VersionId.")
		}
		return v, nil
	}
	stage := model.StageCurrent
	if in.VersionStage != nil {
		stage = *in.VersionStage
	}
	v := s.VersionByStage(stage)
	if v == nil {
		return nil, apierr.ResourceNotFound("Secrets Manager can't find the specified secret value for staging label: %s", stage)
	}
	return v, nil
}
