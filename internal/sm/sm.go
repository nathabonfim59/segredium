// Package sm holds what every operation shares: dependencies, ARNs, secret-id resolution and
// common validation.
package sm

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	"github.com/nathabonfim59/segredium/internal/apierr"
	"github.com/nathabonfim59/segredium/internal/config"
	"github.com/nathabonfim59/segredium/internal/model"
	"github.com/nathabonfim59/segredium/internal/store"
)

// Clock is the time source (tests inject a fake).
type Clock interface{ Now() time.Time }

type SystemClock struct{}

func (SystemClock) Now() time.Time { return time.Now().UTC() }

// ReplicaRegion is one requested replica (AddReplicaRegions entry).
type ReplicaRegion struct {
	Region   string
	KmsKeyID string // "" = default key
}

// Replicator manages replicas of PRIMARY secrets.
//
// Sync propagates a primary's state to its replicas. Operations call it after every successful
// mutation of a secret with len(Replicas) > 0 (passing the stored result). Replication failures
// are recorded on the replica status by the implementation; Sync returns an error only for
// internal failures, which callers log and ignore (AWS reports replication failures through
// ReplicationStatus, not on the write).
//
// AddReplicas validates and creates replicas of the stored primary (region + ARN) and returns
// the updated primary plus the ReplicationStatus list to put in the response. It is what
// ReplicateSecretToRegions and CreateSecret with AddReplicaRegions (after the
// secret is stored) both call. Validation failures are *apierr.Error.
type Replicator interface {
	Sync(ctx context.Context, primary *model.Secret) error
	AddReplicas(ctx context.Context, region, primaryARN string, add []ReplicaRegion, forceOverwrite bool) (*model.Secret, []model.ReplicationStatus, error)
}

// NopReplicator is the default until a replicator is wired: Sync does nothing and
// AddReplicas rejects the request.
type NopReplicator struct{}

func (NopReplicator) Sync(context.Context, *model.Secret) error { return nil }
func (NopReplicator) AddReplicas(context.Context, string, string, []ReplicaRegion, bool) (*model.Secret, []model.ReplicationStatus, error) {
	return nil, nil, apierr.InvalidRequest("Replication is not enabled on this server.")
}

// Deps is everything an operation handler may use.
type Deps struct {
	Store      store.Store
	Clock      Clock
	Rand       io.Reader // crypto-quality randomness (ARN suffixes, UUIDs, passwords)
	Config     *config.Config
	Replicator Replicator
	Log        *slog.Logger
}

// AccountID is the account all ARNs are minted for.
func (d *Deps) AccountID() string { return d.Config.Server.AccountID }

// Now returns the clock's current time in UTC.
func (d *Deps) Now() time.Time { return d.Clock.Now().UTC() }

// NewTestDeps returns Deps over a fresh store with a fixed clock, for tests.
func NewTestDeps(s store.Store, clock Clock) *Deps {
	cfg := config.Default()
	return &Deps{Store: s, Clock: clock, Rand: rand.Reader, Config: cfg, Replicator: NopReplicator{}, Log: slog.New(slog.DiscardHandler)}
}

// FakeClock is a settable clock for tests.
type FakeClock struct{ T time.Time }

func (c *FakeClock) Now() time.Time                  { return c.T }
func (c *FakeClock) Advance(d time.Duration)         { c.T = c.T.Add(d) }
func NewFakeClock(t time.Time) *FakeClock            { return &FakeClock{T: t.UTC()} }
func (c *FakeClock) String() string                  { return c.T.Format(time.RFC3339Nano) }
func (c *FakeClock) Set(t time.Time)                 { c.T = t.UTC() }
func (c *FakeClock) Since(t time.Time) time.Duration { return c.T.Sub(t) }

// Partition returns the ARN partition for a region.
func Partition(region string) string {
	switch {
	case strings.HasPrefix(region, "cn-"):
		return "aws-cn"
	case strings.HasPrefix(region, "us-gov-"):
		return "aws-us-gov"
	case strings.HasPrefix(region, "us-iso-"):
		return "aws-iso"
	case strings.HasPrefix(region, "us-isob-"):
		return "aws-iso-b"
	default:
		return "aws"
	}
}

const suffixAlphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

// NewARN mints a secret ARN: arn:<partition>:secretsmanager:<region>:<account>:secret:<name>-<6 random>.
func (d *Deps) NewARN(region, name string) (string, error) {
	suffix, err := RandomString(d.Rand, 6, suffixAlphabet)
	if err != nil {
		return "", err
	}
	return ARN(region, d.AccountID(), name, suffix), nil
}

// ReplicaARN returns the ARN a replica of primaryARN gets in region (same name and suffix).
func ReplicaARN(primaryARN, region string) string {
	p, err := ParseARN(primaryARN)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("arn:%s:secretsmanager:%s:%s:secret:%s", Partition(region), region, p.Account, p.Resource)
}

// ARN formats a secret ARN.
func ARN(region, account, name, suffix string) string {
	return fmt.Sprintf("arn:%s:secretsmanager:%s:%s:secret:%s-%s", Partition(region), region, account, name, suffix)
}

// ParsedARN is a secret ARN split into parts. Resource is everything after "secret:".
type ParsedARN struct {
	Partition, Region, Account, Resource string
}

// ParseARN parses arn:<p>:secretsmanager:<region>:<account>:secret:<resource>.
func ParseARN(s string) (ParsedARN, error) {
	parts := strings.SplitN(s, ":", 7)
	if len(parts) != 7 || parts[0] != "arn" || parts[2] != "secretsmanager" || parts[5] != "secret" || parts[6] == "" {
		return ParsedARN{}, errors.New("not a secretsmanager secret ARN")
	}
	return ParsedARN{Partition: parts[1], Region: parts[3], Account: parts[4], Resource: parts[6]}, nil
}

// MsgNotFound is AWS's message for an unknown secret.
const MsgNotFound = "Secrets Manager can't find the specified secret."

// Resolve finds the secret a SecretId refers to in region. SecretId may be a name, a full ARN,
// or a partial ARN (ARN without the 6-character suffix). Deleted (scheduled) secrets ARE
// returned; each operation decides how to treat them. Not found → ResourceNotFoundException.
func (d *Deps) Resolve(ctx context.Context, region, secretID string) (*model.Secret, error) {
	s, err := d.lookup(ctx, region, secretID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, apierr.ResourceNotFound(MsgNotFound)
	}
	if err != nil {
		return nil, apierr.Internal("%s", err.Error())
	}
	return s, nil
}

func (d *Deps) lookup(ctx context.Context, region, id string) (*model.Secret, error) {
	if !strings.HasPrefix(id, "arn:") {
		return d.Store.GetSecretByName(ctx, region, id)
	}
	p, err := ParseARN(id)
	if err != nil || p.Region != region || p.Account != d.AccountID() {
		return nil, store.ErrNotFound
	}
	s, err := d.Store.GetSecretByARN(ctx, region, id)
	if err == nil || !errors.Is(err, store.ErrNotFound) {
		return s, err
	}
	// Partial ARN: the resource is the bare name.
	s, err = d.Store.GetSecretByName(ctx, region, p.Resource)
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(s.ARN, id+"-") {
		return nil, store.ErrNotFound
	}
	return s, nil
}

// RandomString draws n characters uniformly from alphabet.
func RandomString(r io.Reader, n int, alphabet string) (string, error) {
	if len(alphabet) == 0 || len(alphabet) > 256 {
		return "", errors.New("bad alphabet")
	}
	out := make([]byte, 0, n)
	buf := make([]byte, 1)
	limit := 256 - 256%len(alphabet) // rejection sampling: no modulo bias
	for len(out) < n {
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", err
		}
		if int(buf[0]) >= limit {
			continue
		}
		out = append(out, alphabet[int(buf[0])%len(alphabet)])
	}
	return string(out), nil
}

// NewUUID returns a random RFC 4122 v4 UUID (the format of ClientRequestToken / VersionId).
func NewUUID(r io.Reader) (string, error) {
	var b [16]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return "", err
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

// UUID is NewUUID over d.Rand.
func (d *Deps) UUID() (string, error) { return NewUUID(d.Rand) }
