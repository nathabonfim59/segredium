package ops

import (
	"context"

	"github.com/nathabonfim59/segredium/internal/api"
	"github.com/nathabonfim59/segredium/internal/awsjson"
	"github.com/nathabonfim59/segredium/internal/model"
	"github.com/nathabonfim59/segredium/internal/sm"
)

func init() { api.Register("DescribeSecret", describeSecret) }

type describeSecretInput struct {
	SecretID *string `json:"SecretId"`
}

type describeSecretOutput struct {
	secretMetadata
	VersionIDsToStages map[string][]string   `json:"VersionIdsToStages,omitempty"`
	ReplicationStatus  []replicationMetadata `json:"ReplicationStatus,omitempty"`
}

type replicationMetadata struct {
	Region           string        `json:"Region,omitempty"`
	KmsKeyID         string        `json:"KmsKeyId,omitempty"`
	Status           string        `json:"Status,omitempty"`
	StatusMessage    string        `json:"StatusMessage,omitempty"`
	LastAccessedDate *awsjson.Time `json:"LastAccessedDate,omitempty"`
}

func describeSecret(ctx context.Context, d *sm.Deps, r *api.Request) (any, error) {
	var in describeSecretInput
	if err := r.Decode(&in); err != nil {
		return nil, err
	}
	var validator sm.Validator
	validator.Required("secretId", in.SecretID != nil)
	validator.Length("secretId", in.SecretID, 1, 2048)
	if err := validator.Err(); err != nil {
		return nil, err
	}
	s, err := d.Resolve(ctx, r.Region, *in.SecretID)
	if err != nil {
		return nil, err
	}
	if !d.CanAccess(r.Identity.UID, s) {
		return nil, sm.AccessDenied("DescribeSecret")
	}
	out := &describeSecretOutput{secretMetadata: metadata(s), VersionIDsToStages: labeledVersions(s)}
	if len(s.Replicas) != 0 {
		out.ReplicationStatus = make([]replicationMetadata, len(s.Replicas))
	}
	for i, replica := range s.Replicas {
		key := replica.KmsKeyID
		if key == model.DefaultKMSKeyID {
			key = ""
		}
		out.ReplicationStatus[i] = replicationMetadata{
			Region: replica.Region, KmsKeyID: key, Status: replica.Status, StatusMessage: replica.StatusMessage,
			LastAccessedDate: accessedDay(replica.LastAccessedDate),
		}
	}
	return out, nil
}
