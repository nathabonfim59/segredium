// Package model holds the stored shape of a secret. Every operation and store backend shares it.
//
// A Secret owns its versions. Stores return deep copies (Clone) so callers can mutate freely
// and persist through store.Store.UpdateSecret.
package model

import (
	"slices"
	"time"
)

// Well-known staging labels.
const (
	StageCurrent  = "AWSCURRENT"
	StagePrevious = "AWSPREVIOUS"
	StagePending  = "AWSPENDING"
)

// DefaultKMSKeyID is what DescribeSecret omits/reports when no KmsKeyId was given.
const DefaultKMSKeyID = "alias/aws/secretsmanager"

type Tag struct {
	Key   string `json:"Key"`
	Value string `json:"Value"`
}

type RotationRules struct {
	AutomaticallyAfterDays *int64  `json:"AutomaticallyAfterDays,omitempty"`
	Duration               *string `json:"Duration,omitempty"`
	ScheduleExpression     *string `json:"ScheduleExpression,omitempty"`
}

// ReplicationStatus is one replica entry on a PRIMARY secret.
type ReplicationStatus struct {
	Region           string     `json:"Region"`
	KmsKeyID         string     `json:"KmsKeyId,omitempty"`
	Status           string     `json:"Status"` // InSync | Failed | InProgress
	StatusMessage    string     `json:"StatusMessage,omitempty"`
	LastAccessedDate *time.Time `json:"LastAccessedDate,omitempty"`
}

// Version is one secret version. Exactly one of SecretString / SecretBinary is set
// (both nil only for a version created without a value, which AWS does not allow, except
// CreateSecret without a value creates NO version at all).
type Version struct {
	VersionID        string     `json:"VersionId"`
	SecretString     *string    `json:"SecretString,omitempty"`
	SecretBinary     []byte     `json:"SecretBinary,omitempty"`
	Stages           []string   `json:"Stages,omitempty"` // staging labels attached to this version
	CreatedDate      time.Time  `json:"CreatedDate"`
	LastAccessedDate *time.Time `json:"LastAccessedDate,omitempty"` // truncated to the day (UTC)
	KmsKeyIDs        []string   `json:"KmsKeyIds,omitempty"`
}

// HasStage reports whether the version carries label.
func (v *Version) HasStage(label string) bool { return slices.Contains(v.Stages, label) }

type Secret struct {
	// Identity. Region is the partition the secret lives in; ARN is unique across the server.
	ARN    string `json:"ARN"`
	Name   string `json:"Name"`
	Region string `json:"Region"`

	Description string `json:"Description,omitempty"`
	KmsKeyID    string `json:"KmsKeyId,omitempty"` // "" = default aws/secretsmanager key
	Tags        []Tag  `json:"Tags,omitempty"`     // insertion order preserved
	Type        string `json:"Type,omitempty"`     // reserved for managed external secrets

	CreatedDate      time.Time  `json:"CreatedDate"`
	LastChangedDate  *time.Time `json:"LastChangedDate,omitempty"`
	LastAccessedDate *time.Time `json:"LastAccessedDate,omitempty"` // truncated to the day (UTC)
	DeletedDate      *time.Time `json:"DeletedDate,omitempty"`      // set = scheduled for deletion
	// DeletionDate is when the purger hard-deletes the secret (DeletedDate + recovery window).
	DeletionDate *time.Time `json:"DeletionDate,omitempty"`

	// Rotation (written by rotation, read by DescribeSecret/ListSecrets).
	RotationEnabled   bool           `json:"RotationEnabled,omitempty"`
	RotationLambdaARN string         `json:"RotationLambdaARN,omitempty"`
	RotationRules     *RotationRules `json:"RotationRules,omitempty"`
	// Managed external secret rotation (RotateSecret/DescribeSecret members, stored verbatim).
	ExternalSecretRotationMetadata []Tag      `json:"ExternalSecretRotationMetadata,omitempty"` // Key/Value pairs
	ExternalSecretRotationRoleArn  string     `json:"ExternalSecretRotationRoleArn,omitempty"`
	LastRotatedDate                *time.Time `json:"LastRotatedDate,omitempty"`
	NextRotationDate               *time.Time `json:"NextRotationDate,omitempty"`

	// Resource policy.
	ResourcePolicy string `json:"ResourcePolicy,omitempty"`

	// Replication. On a primary: Replicas lists its replicas and PrimaryRegion is its
	// own region once it has ever been replicated (AWS reports PrimaryRegion then). On a replica:
	// PrimaryRegion is the primary's region and IsReplica is true.
	PrimaryRegion string              `json:"PrimaryRegion,omitempty"`
	IsReplica     bool                `json:"IsReplica,omitempty"`
	Replicas      []ReplicationStatus `json:"Replicas,omitempty"`

	OwningService string `json:"OwningService,omitempty"`

	// OwnerUID is the local Unix user that created the secret (segredium extension, never
	// sent on the wire). nil = unknown/unowned. Enforced only with server.access_mode=owner.
	OwnerUID *uint32 `json:"OwnerUID,omitempty"`

	Versions []*Version `json:"Versions,omitempty"` // ordered by CreatedDate ascending
}

// Deleted reports whether the secret is scheduled for deletion.
func (s *Secret) Deleted() bool { return s.DeletedDate != nil }

// Version returns the version with id, or nil.
func (s *Secret) Version(id string) *Version {
	for _, v := range s.Versions {
		if v.VersionID == id {
			return v
		}
	}
	return nil
}

// VersionByStage returns the version that carries label, or nil.
func (s *Secret) VersionByStage(label string) *Version {
	for _, v := range s.Versions {
		if v.HasStage(label) {
			return v
		}
	}
	return nil
}

// Clone returns a deep copy.
func (s *Secret) Clone() *Secret {
	if s == nil {
		return nil
	}
	c := *s
	c.Tags = slices.Clone(s.Tags)
	c.OwnerUID = clonePtr(s.OwnerUID)
	c.ExternalSecretRotationMetadata = slices.Clone(s.ExternalSecretRotationMetadata)
	c.LastChangedDate = cloneTime(s.LastChangedDate)
	c.LastAccessedDate = cloneTime(s.LastAccessedDate)
	c.DeletedDate = cloneTime(s.DeletedDate)
	c.DeletionDate = cloneTime(s.DeletionDate)
	c.LastRotatedDate = cloneTime(s.LastRotatedDate)
	c.NextRotationDate = cloneTime(s.NextRotationDate)
	if s.RotationRules != nil {
		r := *s.RotationRules
		r.AutomaticallyAfterDays = clonePtr(s.RotationRules.AutomaticallyAfterDays)
		r.Duration = clonePtr(s.RotationRules.Duration)
		r.ScheduleExpression = clonePtr(s.RotationRules.ScheduleExpression)
		c.RotationRules = &r
	}
	if s.Replicas != nil {
		c.Replicas = make([]ReplicationStatus, len(s.Replicas))
		for i, r := range s.Replicas {
			r.LastAccessedDate = cloneTime(r.LastAccessedDate)
			c.Replicas[i] = r
		}
	}
	if s.Versions != nil {
		c.Versions = make([]*Version, len(s.Versions))
		for i, v := range s.Versions {
			c.Versions[i] = v.Clone()
		}
	}
	return &c
}

// CloneMeta is Clone without secret values: every version's SecretString and SecretBinary are
// nil. Used for listing so secret payloads are never copied.
func (s *Secret) CloneMeta() *Secret {
	if s == nil {
		return nil
	}
	vs := s.Versions
	c := *s
	c.Versions = nil
	out := c.Clone()
	if vs != nil {
		out.Versions = make([]*Version, len(vs))
		for i, v := range vs {
			m := *v
			m.SecretString, m.SecretBinary = nil, nil
			out.Versions[i] = m.Clone()
		}
	}
	return out
}

// Clone returns a deep copy.
func (v *Version) Clone() *Version {
	if v == nil {
		return nil
	}
	c := *v
	c.SecretString = clonePtr(v.SecretString)
	if v.SecretBinary != nil {
		c.SecretBinary = slices.Clone(v.SecretBinary)
	}
	c.Stages = slices.Clone(v.Stages)
	c.LastAccessedDate = cloneTime(v.LastAccessedDate)
	c.KmsKeyIDs = slices.Clone(v.KmsKeyIDs)
	return &c
}

func cloneTime(t *time.Time) *time.Time { return clonePtr(t) }

func clonePtr[T any](p *T) *T {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}

// Day truncates t to midnight UTC (AWS reports LastAccessedDate at day granularity).
func Day(t time.Time) time.Time {
	t = t.UTC()
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
}
