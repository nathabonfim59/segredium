package ops

import (
	"time"

	"github.com/nathabonfim59/segredium/internal/awsjson"
	"github.com/nathabonfim59/segredium/internal/model"
)

// secretMetadata contains the members shared by the service model's
// DescribeSecretResponse and SecretListEntry, never the stored owner or values.
type secretMetadata struct {
	ARN                            string               `json:"ARN"`
	Name                           string               `json:"Name"`
	Type                           string               `json:"Type,omitempty"`
	Description                    string               `json:"Description,omitempty"`
	KmsKeyID                       string               `json:"KmsKeyId,omitempty"`
	RotationEnabled                *bool                `json:"RotationEnabled,omitempty"`
	RotationLambdaARN              string               `json:"RotationLambdaARN,omitempty"`
	RotationRules                  *model.RotationRules `json:"RotationRules,omitempty"`
	ExternalSecretRotationMetadata []model.Tag          `json:"ExternalSecretRotationMetadata,omitempty"`
	ExternalSecretRotationRoleArn  string               `json:"ExternalSecretRotationRoleArn,omitempty"`
	LastRotatedDate                *awsjson.Time        `json:"LastRotatedDate,omitempty"`
	LastChangedDate                *awsjson.Time        `json:"LastChangedDate,omitempty"`
	LastAccessedDate               *awsjson.Time        `json:"LastAccessedDate,omitempty"`
	DeletedDate                    *awsjson.Time        `json:"DeletedDate,omitempty"`
	NextRotationDate               *awsjson.Time        `json:"NextRotationDate,omitempty"`
	Tags                           []model.Tag          `json:"Tags,omitempty"`
	OwningService                  string               `json:"OwningService,omitempty"`
	CreatedDate                    *awsjson.Time        `json:"CreatedDate,omitempty"`
	PrimaryRegion                  string               `json:"PrimaryRegion,omitempty"`
}

func metadata(s *model.Secret) secretMetadata {
	out := secretMetadata{
		ARN: s.ARN, Name: s.Name, Type: s.Type, Description: s.Description,
		KmsKeyID: s.KmsKeyID, RotationLambdaARN: s.RotationLambdaARN, RotationRules: s.RotationRules,
		ExternalSecretRotationMetadata: s.ExternalSecretRotationMetadata,
		ExternalSecretRotationRoleArn:  s.ExternalSecretRotationRoleArn,
		LastRotatedDate:                awsjson.TimePtr(s.LastRotatedDate), LastChangedDate: awsjson.TimePtr(s.LastChangedDate),
		LastAccessedDate: accessedDay(s.LastAccessedDate),
		NextRotationDate: awsjson.TimePtr(s.NextRotationDate), Tags: s.Tags,
		OwningService: s.OwningService, CreatedDate: awsjson.NewTime(s.CreatedDate), PrimaryRegion: s.PrimaryRegion,
	}
	// Both APIs report the deletion request time; the purge deadline is DeleteSecret.DeletionDate.
	out.DeletedDate = awsjson.TimePtr(s.DeletedDate)
	if out.KmsKeyID == model.DefaultKMSKeyID {
		out.KmsKeyID = ""
	}
	// The model omits RotationEnabled until rotation has been configured, including
	// after cancellation, when its previous configuration remains on the secret.
	if s.RotationEnabled || s.RotationRules != nil || s.RotationLambdaARN != "" || s.LastRotatedDate != nil ||
		s.NextRotationDate != nil || len(s.ExternalSecretRotationMetadata) != 0 || s.ExternalSecretRotationRoleArn != "" {
		out.RotationEnabled = &s.RotationEnabled
	}
	return out
}

func accessedDay(t *time.Time) *awsjson.Time {
	if t == nil || t.IsZero() {
		return nil
	}
	return awsjson.NewTime(model.Day(*t))
}

func labeledVersions(s *model.Secret) map[string][]string {
	var out map[string][]string
	for _, v := range s.Versions {
		if len(v.Stages) == 0 {
			continue
		}
		if out == nil {
			out = make(map[string][]string)
		}
		out[v.VersionID] = v.Stages
	}
	return out
}
