package ops

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/nathabonfim59/segredium/internal/api"
	"github.com/nathabonfim59/segredium/internal/apierr"
	"github.com/nathabonfim59/segredium/internal/awsjson"
	"github.com/nathabonfim59/segredium/internal/model"
	"github.com/nathabonfim59/segredium/internal/sm"
	"github.com/nathabonfim59/segredium/internal/store"
	"github.com/nathabonfim59/segredium/internal/versions"
)

func init() { api.Register("CreateSecret", createSecret) }

type createSecretInput struct {
	Name                        *string                `json:"Name"`
	ClientRequestToken          *string                `json:"ClientRequestToken"`
	Description                 *string                `json:"Description"`
	KmsKeyID                    *string                `json:"KmsKeyId"`
	SecretBinary                []byte                 `json:"SecretBinary"`
	SecretString                *string                `json:"SecretString"`
	Tags                        []*createTag           `json:"Tags"`
	AddReplicaRegions           []*createReplicaRegion `json:"AddReplicaRegions"`
	ForceOverwriteReplicaSecret bool                   `json:"ForceOverwriteReplicaSecret"`
	Type                        *string                `json:"Type"`
}

type createTag struct {
	Key   *string `json:"Key"`
	Value *string `json:"Value"`
}

type createReplicaRegion struct {
	Region   *string `json:"Region"`
	KmsKeyID *string `json:"KmsKeyId"`
}

type replicationStatusOutput struct {
	Region           string        `json:"Region,omitempty"`
	KmsKeyID         string        `json:"KmsKeyId,omitempty"`
	Status           string        `json:"Status,omitempty"`
	StatusMessage    string        `json:"StatusMessage,omitempty"`
	LastAccessedDate *awsjson.Time `json:"LastAccessedDate,omitempty"`
}

type createSecretOutput struct {
	ARN               string                    `json:"ARN"`
	Name              string                    `json:"Name"`
	VersionID         string                    `json:"VersionId,omitempty"`
	ReplicationStatus []replicationStatusOutput `json:"ReplicationStatus,omitempty"`
}

// Name character rules are service validation, not a service-2.json pattern constraint.
var secretNamePattern = regexp.MustCompile(`^[a-zA-Z0-9/_+=.@-]+$`)
var replicaRegionPattern = regexp.MustCompile(`^([a-z]+-)+\d+$`)
var tagPattern = regexp.MustCompile(`^[\p{L}\p{Z}\p{N}_.:/=+\-@]*$`)

func createSecret(ctx context.Context, d *sm.Deps, r *api.Request) (any, error) {
	var in createSecretInput
	if err := r.Decode(&in); err != nil {
		return nil, err
	}
	if err := in.validate(); err != nil {
		return nil, err
	}
	if !d.CanAccess(r.Identity.UID, &model.Secret{OwnerUID: r.Identity.UID}) {
		return nil, sm.AccessDenied("CreateSecret")
	}
	arn, err := d.NewARN(r.Region, *in.Name)
	if err != nil {
		return nil, err
	}
	now := d.Now()
	s := &model.Secret{ARN: arn, Name: *in.Name, Region: r.Region, CreatedDate: now, LastChangedDate: &now, Description: stringValue(in.Description), KmsKeyID: stringValue(in.KmsKeyID), Type: stringValue(in.Type)}
	if r.Identity.UID != nil {
		uid := *r.Identity.UID
		s.OwnerUID = &uid
	}
	for _, tag := range in.Tags {
		s.Tags = append(s.Tags, model.Tag{Key: *tag.Key, Value: stringValue(tag.Value)})
	}
	versionID := ""
	if in.SecretString != nil || in.SecretBinary != nil {
		versionID = stringValue(in.ClientRequestToken)
		if versionID == "" {
			// The model marks this idempotency token optional. Accept raw HTTP clients
			// that omit it by generating the UUID that AWS SDKs normally supply.
			versionID, err = d.UUID()
			if err != nil {
				return nil, err
			}
		}
		key := s.KmsKeyID
		if key == "" {
			key = model.DefaultKMSKeyID
		}
		s.Versions = []*model.Version{{VersionID: versionID, SecretString: in.SecretString, SecretBinary: in.SecretBinary, Stages: []string{model.StageCurrent}, CreatedDate: now, KmsKeyIDs: []string{key}}}
	}
	if err := d.Store.CreateSecret(ctx, s); err != nil {
		if !errors.Is(err, store.ErrExists) {
			return nil, err
		}
		// Let the unique-name write arbitrate concurrent creates; only a collision needs a read.
		existing, err := d.Store.GetSecretByName(ctx, r.Region, s.Name)
		if err != nil {
			return nil, storeError(err)
		}
		if !d.CanAccess(r.Identity.UID, existing) {
			return nil, sm.AccessDenied("CreateSecret")
		}
		if existing.Deleted() {
			return nil, apierr.InvalidRequest("You can't create this secret because a secret with this name is already scheduled for deletion.")
		}
		if in.ClientRequestToken != nil {
			if v := existing.Version(*in.ClientRequestToken); v != nil {
				if !versions.SameValue(v, in.SecretString, in.SecretBinary) {
					return nil, apierr.ResourceExists(msgTokenConflict)
				}
				return createOutput(existing, v.VersionID, existing.Replicas), nil
			}
		}
		return nil, apierr.ResourceExists("The operation failed because the secret %s already exists.", s.Name)
	}
	if len(in.AddReplicaRegions) > 0 {
		add := make([]sm.ReplicaRegion, len(in.AddReplicaRegions))
		for i, reg := range in.AddReplicaRegions {
			add[i] = sm.ReplicaRegion{Region: *reg.Region, KmsKeyID: stringValue(reg.KmsKeyID)}
		}
		primary, statuses, err := d.Replicator.AddReplicas(ctx, r.Region, s.ARN, add, in.ForceOverwriteReplicaSecret)
		if err != nil {
			return nil, err
		}
		return createOutput(primary, versionID, statuses), nil
	}
	return createOutput(s, versionID, nil), nil
}

func (in *createSecretInput) validate() error {
	var v sm.Validator
	// Constraints from botocore secretsmanager/2017-10-17/service-2.json.
	v.Required("name", in.Name != nil)
	v.Length("name", in.Name, 1, 512)
	v.Length("clientRequestToken", in.ClientRequestToken, 32, 64)
	v.Length("description", in.Description, 0, 2048)
	v.Length("kmsKeyId", in.KmsKeyID, 0, 2048)
	v.Length("type", in.Type, 0, 256)
	validateValue(&v, in.SecretString, in.SecretBinary)
	for i, tag := range in.Tags {
		if tag == nil {
			v.Custom(fmt.Sprintf("Value null at 'tags.%d' failed to satisfy constraint: Member must not be null", i+1))
			continue
		}
		v.Length(fmt.Sprintf("tags.%d.member.key", i+1), tag.Key, 1, 128)
		v.Length(fmt.Sprintf("tags.%d.member.value", i+1), tag.Value, 0, 256)
	}
	if in.AddReplicaRegions != nil && len(in.AddReplicaRegions) == 0 {
		v.Custom("Value '[]' at 'addReplicaRegions' failed to satisfy constraint: Member must have length greater than or equal to 1")
	}
	for i, reg := range in.AddReplicaRegions {
		if reg == nil {
			v.Custom(fmt.Sprintf("Value null at 'addReplicaRegions.%d' failed to satisfy constraint: Member must not be null", i+1))
			continue
		}
		member := fmt.Sprintf("addReplicaRegions.%d.member", i+1)
		v.Length(member+".region", reg.Region, 1, 128)
		v.Pattern(member+".region", reg.Region, replicaRegionPattern)
		v.Length(member+".kmsKeyId", reg.KmsKeyID, 0, 2048)
	}
	if err := v.Err(); err != nil {
		return err
	}
	if !secretNamePattern.MatchString(*in.Name) {
		return apierr.InvalidParameter("Invalid name. Must be a valid name containing alphanumeric characters, or any of the following: -/_+=.@!")
	}
	if err := valueConflict(in.SecretString, in.SecretBinary, false); err != nil {
		return err
	}
	if len(in.Tags) > 50 {
		return apierr.InvalidParameter("You can't have more than 50 tags for a secret.")
	}
	for _, tag := range in.Tags {
		if tag.Key == nil || !tagPattern.MatchString(*tag.Key) || strings.HasPrefix(strings.ToLower(*tag.Key), "aws:") {
			return apierr.InvalidParameter("Invalid tag key.")
		}
		if tag.Value != nil && !tagPattern.MatchString(*tag.Value) {
			return apierr.InvalidParameter("Invalid tag value.")
		}
	}
	for _, reg := range in.AddReplicaRegions {
		if reg.Region == nil {
			return apierr.InvalidParameter("You must specify a Region for each replica.")
		}
	}
	return nil
}

func createOutput(s *model.Secret, versionID string, replicas []model.ReplicationStatus) *createSecretOutput {
	out := &createSecretOutput{ARN: s.ARN, Name: s.Name, VersionID: versionID}
	if len(replicas) > 0 {
		out.ReplicationStatus = make([]replicationStatusOutput, len(replicas))
		for i, reg := range replicas {
			out.ReplicationStatus[i] = replicationStatusOutput{Region: reg.Region, KmsKeyID: reg.KmsKeyID, Status: reg.Status, StatusMessage: reg.StatusMessage, LastAccessedDate: awsjson.TimePtr(reg.LastAccessedDate)}
		}
	}
	return out
}

func stringValue(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
