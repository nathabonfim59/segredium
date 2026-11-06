package sm_test

import (
	"bytes"
	"context"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/nathabonfim59/segredium/internal/apierr"
	"github.com/nathabonfim59/segredium/internal/model"
	"github.com/nathabonfim59/segredium/internal/sm"
	"github.com/nathabonfim59/segredium/internal/store/memstore"
)

func TestARN(t *testing.T) {
	d := sm.NewTestDeps(memstore.New(), sm.NewFakeClock(time.Now()))
	arn, err := d.NewARN("us-east-1", "prod/db")
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/db-[A-Za-z0-9]{6}$`).MatchString(arn) {
		t.Fatal(arn)
	}
	if got := sm.ARN("cn-north-1", "1", "n", "abcdef"); !strings.HasPrefix(got, "arn:aws-cn:") {
		t.Fatal(got)
	}
	p, err := sm.ParseARN(arn)
	if err != nil || p.Region != "us-east-1" || !strings.HasPrefix(p.Resource, "prod/db-") {
		t.Fatalf("%+v %v", p, err)
	}
	if r := sm.ReplicaARN(arn, "eu-west-1"); r != strings.Replace(arn, "us-east-1", "eu-west-1", 1) {
		t.Fatal(r)
	}
}

func TestResolve(t *testing.T) {
	ctx := context.Background()
	d := sm.NewTestDeps(memstore.New(), sm.NewFakeClock(time.Now()))
	arn := sm.ARN("us-east-1", d.AccountID(), "app/key-abc", "XyZ123")
	if err := d.Store.CreateSecret(ctx, &model.Secret{ARN: arn, Name: "app/key-abc", Region: "us-east-1"}); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"app/key-abc", arn, strings.TrimSuffix(arn, "-XyZ123")} {
		s, err := d.Resolve(ctx, "us-east-1", id)
		if err != nil || s.ARN != arn {
			t.Errorf("%s: %v %v", id, s, err)
		}
	}
	for _, id := range []string{"app/key", arn + "x", strings.TrimSuffix(arn, "3"), strings.Replace(arn, "us-east-1", "eu-west-1", 1),
		strings.Replace(arn, d.AccountID(), "999999999999", 1), "arn:aws:secretsmanager:us-east-1:123456789012:secret:app"} {
		_, err := d.Resolve(ctx, "us-east-1", id)
		if !errors.Is(err, apierr.ResourceNotFound("")) {
			t.Errorf("%s: want ResourceNotFound, got %v", id, err)
		}
	}
	if _, err := d.Resolve(ctx, "eu-west-1", "app/key-abc"); !errors.Is(err, apierr.ResourceNotFound("")) {
		t.Error("other region must not resolve")
	}
}

func TestRandomAndUUID(t *testing.T) {
	// alphabet of 3: limit is 255, so byte 255 is rejected (no modulo bias).
	s, err := sm.RandomString(bytes.NewReader([]byte{255, 0, 1, 255, 5}), 3, "abc")
	if err != nil || s != "abc" {
		t.Fatalf("%q %v", s, err)
	}
}

func TestUUIDFormat(t *testing.T) {
	d := sm.NewTestDeps(memstore.New(), sm.NewFakeClock(time.Now()))
	u, err := d.UUID()
	if err != nil || !regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`).MatchString(u) {
		t.Fatal(u, err)
	}
}

func TestValidator(t *testing.T) {
	var v sm.Validator
	long := strings.Repeat("x", 2049)
	n := int64(3)
	v.Required("secretId", false)
	v.Length("name", &long, 1, 2048)
	v.Range("recoveryWindowInDays", &n, 7, 30)
	err := v.Err()
	e := apierr.As(err)
	if e == nil || e.Code != "ValidationException" || !strings.HasPrefix(e.Message, "3 validation errors detected: Value null at 'secretId'") {
		t.Fatal(err)
	}
	var ok sm.Validator
	if ok.Err() != nil {
		t.Fatal("empty validator must be nil")
	}
}

func TestSensitiveLengthNeverEchoes(t *testing.T) {
	var v sm.Validator
	secret := strings.Repeat("s3cr3t", 20000)
	empty := ""
	v.SensitiveLength("secretString", &secret, 1, 65536)
	v.SensitiveLength("secretString", &empty, 1, 65536)
	msg := v.Err().Error()
	if strings.Contains(msg, "s3cr3t") || strings.Contains(msg, "''") {
		t.Fatalf("value echoed: %.200s", msg)
	}
	if !strings.Contains(msg, "2 validation errors detected: Value at 'secretString' failed to satisfy constraint: Member must have length less than or equal to 65536") {
		t.Fatal(msg)
	}
}

func TestCanAccess(t *testing.T) {
	d := sm.NewTestDeps(memstore.New(), sm.NewFakeClock(time.Now()))
	u := func(n uint32) *uint32 { return &n }
	owned := &model.Secret{OwnerUID: u(1000)}
	unowned := &model.Secret{}
	if !d.CanAccess(nil, owned) {
		t.Fatal("machine mode must allow everyone")
	}
	d.Config.Server.AccessMode = "owner"
	for _, c := range []struct {
		uid  *uint32
		s    *model.Secret
		want bool
	}{{u(1000), owned, true}, {u(1001), owned, false}, {u(0), owned, true}, {nil, owned, false}, {u(1000), unowned, false}, {u(0), unowned, true}} {
		if got := d.CanAccess(c.uid, c.s); got != c.want {
			t.Errorf("uid=%v owner=%v: got %v", c.uid, c.s.OwnerUID, got)
		}
	}
}
