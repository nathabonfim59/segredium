// Package storetest is the conformance suite for store.Store. Every backend's tests call
// storetest.Run with a constructor returning a fresh, empty store.
package storetest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/nathabonfim59/segredium/internal/model"
	"github.com/nathabonfim59/segredium/internal/store"
)

// Run executes the whole suite.
func Run(t *testing.T, newStore func(t *testing.T) store.Store) {
	t.Helper()
	tests := []struct {
		name string
		fn   func(t *testing.T, s store.Store)
	}{
		{"RoundTripAllFields", testRoundTrip},
		{"CreateDuplicateName", testCreateDuplicateName},
		{"CreateDuplicateARN", testCreateDuplicateARN},
		{"SameNameDifferentRegions", testSameNameDifferentRegions},
		{"GetWrongRegion", testGetWrongRegion},
		{"NotFound", testNotFound},
		{"ListOrderAndRegion", testListOrder},
		{"ListRegions", testListRegions},
		{"UpdateAtomicAndPersisted", testUpdate},
		{"UpdateErrorRollsBack", testUpdateError},
		{"UpdateImmutable", testUpdateImmutable},
		{"DeleteFreesName", testDelete},
		{"ReturnedCopiesAreIsolated", testIsolation},
		{"ConcurrentUpdates", testConcurrentUpdates},
		{"ListMetaOmitsValues", testListMeta},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := newStore(t)
			t.Cleanup(func() { _ = s.Close() })
			tc.fn(t, s)
		})
	}
}

var base = time.Date(2026, 11, 6, 12, 30, 45, 123456789, time.UTC)

func ptr[T any](v T) *T { return &v }

// Full returns a secret with every field populated (ns-precision times included).
func Full(region, name string, n int) *model.Secret {
	created := base.Add(time.Duration(n) * time.Second)
	return &model.Secret{
		ARN:              fmt.Sprintf("arn:aws:secretsmanager:%s:123456789012:secret:%s-Ab%04d", region, name, n),
		Name:             name,
		Region:           region,
		Description:      "desc ünïcode " + name,
		KmsKeyID:         "arn:aws:kms:us-east-1:123456789012:key/abc",
		Tags:             []model.Tag{{Key: "z", Value: "1"}, {Key: "a", Value: ""}},
		Type:             "",
		CreatedDate:      created,
		LastChangedDate:  ptr(created.Add(time.Nanosecond)),
		LastAccessedDate: ptr(model.Day(created)),
		DeletedDate:      ptr(created.Add(2 * time.Hour)),
		DeletionDate:     ptr(created.Add(7 * 24 * time.Hour)),
		RotationEnabled:  true, RotationLambdaARN: "arn:aws:lambda:us-east-1:123456789012:function:rot",
		RotationRules: &model.RotationRules{
			AutomaticallyAfterDays: ptr(int64(30)), Duration: ptr("2h"), ScheduleExpression: ptr("rate(10 days)"),
		},
		ExternalSecretRotationMetadata: []model.Tag{{Key: "k", Value: "v"}},
		ExternalSecretRotationRoleArn:  "arn:aws:iam::123456789012:role/r",
		LastRotatedDate:                ptr(created.Add(3 * time.Hour)),
		NextRotationDate:               ptr(created.Add(30 * 24 * time.Hour)),
		ResourcePolicy:                 `{"Version":"2012-10-17","Statement":[]}`,
		PrimaryRegion:                  region,
		Replicas: []model.ReplicationStatus{{
			Region: "eu-west-1", KmsKeyID: "k", Status: "InSync", StatusMessage: "Replication succeeded",
			LastAccessedDate: ptr(model.Day(created)),
		}},
		OwningService: "",
		OwnerUID:      ptr(uint32(1000)),
		Versions: []*model.Version{
			{VersionID: "v1", SecretBinary: []byte{0, 1, 2, 255}, Stages: []string{model.StagePrevious},
				CreatedDate: created, KmsKeyIDs: []string{"DefaultEncryptionKey"}},
			{VersionID: "v2", SecretString: ptr(`{"user":"a","pass":"b\u0000"}`), Stages: []string{model.StageCurrent, "custom"},
				CreatedDate: created.Add(time.Minute), LastAccessedDate: ptr(model.Day(created))},
		},
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func equal(t *testing.T, got, want *model.Secret) {
	t.Helper()
	if g, w := mustJSON(t, got), mustJSON(t, want); g != w {
		t.Fatalf("secret mismatch\n got: %s\nwant: %s", g, w)
	}
}

func create(t *testing.T, s store.Store, sec *model.Secret) {
	t.Helper()
	if err := s.CreateSecret(context.Background(), sec); err != nil {
		t.Fatalf("CreateSecret(%s): %v", sec.Name, err)
	}
}

func testRoundTrip(t *testing.T, s store.Store) {
	ctx := context.Background()
	want := Full("us-east-1", "app/db", 1)
	create(t, s, want)
	got, err := s.GetSecretByARN(ctx, "us-east-1", want.ARN)
	if err != nil {
		t.Fatal(err)
	}
	equal(t, got, want)
	got, err = s.GetSecretByName(ctx, "us-east-1", "app/db")
	if err != nil {
		t.Fatal(err)
	}
	equal(t, got, want)
	// Minimal secret: nil/empty fields must stay nil/empty.
	min := &model.Secret{ARN: "arn:aws:secretsmanager:us-east-1:123456789012:secret:m-AAAAAA", Name: "m", Region: "us-east-1", CreatedDate: base}
	create(t, s, min)
	got, err = s.GetSecretByName(ctx, "us-east-1", "m")
	if err != nil {
		t.Fatal(err)
	}
	equal(t, got, min)
}

func testCreateDuplicateName(t *testing.T, s store.Store) {
	create(t, s, Full("us-east-1", "dup", 1))
	err := s.CreateSecret(context.Background(), Full("us-east-1", "dup", 2))
	if !errors.Is(err, store.ErrExists) {
		t.Fatalf("want ErrExists, got %v", err)
	}
}

func testCreateDuplicateARN(t *testing.T, s store.Store) {
	a := Full("us-east-1", "a", 1)
	create(t, s, a)
	b := Full("us-east-1", "b", 2)
	b.ARN = a.ARN
	if err := s.CreateSecret(context.Background(), b); !errors.Is(err, store.ErrExists) {
		t.Fatalf("want ErrExists, got %v", err)
	}
}

func testSameNameDifferentRegions(t *testing.T, s store.Store) {
	create(t, s, Full("us-east-1", "x", 1))
	create(t, s, Full("eu-west-1", "x", 2))
	got, err := s.GetSecretByName(context.Background(), "eu-west-1", "x")
	if err != nil || got.Region != "eu-west-1" {
		t.Fatalf("got %v %v", got, err)
	}
}

func testGetWrongRegion(t *testing.T, s store.Store) {
	a := Full("us-east-1", "a", 1)
	create(t, s, a)
	if _, err := s.GetSecretByARN(context.Background(), "eu-west-1", a.ARN); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
	if _, err := s.UpdateSecret(context.Background(), "eu-west-1", a.ARN, func(*model.Secret) error { return nil }); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("update: want ErrNotFound, got %v", err)
	}
	if err := s.DeleteSecret(context.Background(), "eu-west-1", a.ARN); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("delete: want ErrNotFound, got %v", err)
	}
}

func testNotFound(t *testing.T, s store.Store) {
	ctx := context.Background()
	if _, err := s.GetSecretByARN(ctx, "us-east-1", "arn:nope"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("got %v", err)
	}
	if _, err := s.GetSecretByName(ctx, "us-east-1", "nope"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("got %v", err)
	}
	if err := s.DeleteSecret(ctx, "us-east-1", "arn:nope"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("got %v", err)
	}
	l, err := s.ListSecrets(ctx, "us-east-1")
	if err != nil || len(l) != 0 {
		t.Fatalf("empty list: %v %v", l, err)
	}
}

func testListOrder(t *testing.T, s store.Store) {
	ctx := context.Background()
	c := Full("us-east-1", "c", 3)
	a := Full("us-east-1", "a", 1)
	b1 := Full("us-east-1", "b1", 2)
	b2 := Full("us-east-1", "b2", 2) // same CreatedDate as b1: tie broken by ARN
	b2.ARN = "arn:aws:secretsmanager:us-east-1:123456789012:secret:b0-zzzzzz"
	other := Full("eu-west-1", "o", 0)
	for _, x := range []*model.Secret{c, b1, other, a, b2} {
		create(t, s, x)
	}
	l, err := s.ListSecrets(ctx, "us-east-1")
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, x := range l {
		names = append(names, x.Name)
	}
	if fmt.Sprint(names) != "[a b2 b1 c]" {
		t.Fatalf("order: %v", names)
	}
	equal(t, l[0], a)
}

func testListRegions(t *testing.T, s store.Store) {
	ctx := context.Background()
	create(t, s, Full("us-west-2", "a", 1))
	create(t, s, Full("eu-west-1", "a", 2))
	x := Full("ap-south-1", "a", 3)
	create(t, s, x)
	if err := s.DeleteSecret(ctx, "ap-south-1", x.ARN); err != nil {
		t.Fatal(err)
	}
	r, err := s.ListRegions(ctx)
	if err != nil || fmt.Sprint(r) != "[eu-west-1 us-west-2]" {
		t.Fatalf("regions %v %v", r, err)
	}
}

func testUpdate(t *testing.T, s store.Store) {
	ctx := context.Background()
	a := Full("us-east-1", "a", 1)
	create(t, s, a)
	got, err := s.UpdateSecret(ctx, "us-east-1", a.ARN, func(x *model.Secret) error {
		x.Description = "new"
		x.Tags = nil
		x.DeletedDate = nil
		x.Versions = append(x.Versions, &model.Version{VersionID: "v3", SecretString: ptr("s"), Stages: []string{model.StagePending}, CreatedDate: base})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	want := a.Clone()
	want.Description, want.Tags, want.DeletedDate = "new", nil, nil
	want.Versions = append(want.Versions, &model.Version{VersionID: "v3", SecretString: ptr("s"), Stages: []string{model.StagePending}, CreatedDate: base})
	equal(t, got, want)
	again, err := s.GetSecretByName(ctx, "us-east-1", "a")
	if err != nil {
		t.Fatal(err)
	}
	equal(t, again, want)
}

func testUpdateError(t *testing.T, s store.Store) {
	ctx := context.Background()
	a := Full("us-east-1", "a", 1)
	create(t, s, a)
	boom := errors.New("boom")
	_, err := s.UpdateSecret(ctx, "us-east-1", a.ARN, func(x *model.Secret) error {
		x.Description = "changed"
		return boom
	})
	if err != boom {
		t.Fatalf("want the fn error unchanged, got %v", err)
	}
	got, _ := s.GetSecretByARN(ctx, "us-east-1", a.ARN)
	equal(t, got, a)
}

func testUpdateImmutable(t *testing.T, s store.Store) {
	ctx := context.Background()
	a := Full("us-east-1", "a", 1)
	create(t, s, a)
	for _, mut := range []func(*model.Secret){
		func(x *model.Secret) { x.Name = "b" },
		func(x *model.Secret) { x.ARN = "arn:other" },
		func(x *model.Secret) { x.Region = "eu-west-1" },
	} {
		_, err := s.UpdateSecret(ctx, "us-east-1", a.ARN, func(x *model.Secret) error { mut(x); return nil })
		if !errors.Is(err, store.ErrImmutable) {
			t.Fatalf("want ErrImmutable, got %v", err)
		}
	}
	got, _ := s.GetSecretByARN(ctx, "us-east-1", a.ARN)
	equal(t, got, a)
}

func testDelete(t *testing.T, s store.Store) {
	ctx := context.Background()
	a := Full("us-east-1", "a", 1)
	create(t, s, a)
	if err := s.DeleteSecret(ctx, "us-east-1", a.ARN); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetSecretByARN(ctx, "us-east-1", a.ARN); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("after delete: %v", err)
	}
	b := Full("us-east-1", "a", 2) // same name, new ARN
	create(t, s, b)
}

func testIsolation(t *testing.T, s store.Store) {
	ctx := context.Background()
	a := Full("us-east-1", "a", 1)
	create(t, s, a)
	a.Description = "mutated after create"
	a.Versions[1].Stages[0] = "X"
	got, _ := s.GetSecretByARN(ctx, "us-east-1", a.ARN)
	if got.Description == "mutated after create" || got.Versions[1].Stages[0] == "X" {
		t.Fatal("store aliases the caller's secret")
	}
	got.Versions[0].SecretBinary[0] = 9
	got.Tags[0].Key = "mut"
	again, _ := s.GetSecretByARN(ctx, "us-east-1", a.ARN)
	if again.Versions[0].SecretBinary[0] == 9 || again.Tags[0].Key == "mut" {
		t.Fatal("store returned an aliased copy")
	}
	var kept *model.Secret
	upd, _ := s.UpdateSecret(ctx, "us-east-1", a.ARN, func(x *model.Secret) error { kept = x; return nil })
	kept.Description = "late"
	upd.Description = "late2"
	again, _ = s.GetSecretByARN(ctx, "us-east-1", a.ARN)
	if again.Description == "late" || again.Description == "late2" {
		t.Fatal("UpdateSecret leaked a reference to stored state")
	}
}

func testConcurrentUpdates(t *testing.T, s store.Store) {
	ctx := context.Background()
	a := &model.Secret{ARN: "arn:aws:secretsmanager:us-east-1:123456789012:secret:c-AAAAAA", Name: "c", Region: "us-east-1", CreatedDate: base}
	create(t, s, a)
	const n = 50
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := s.UpdateSecret(ctx, "us-east-1", a.ARN, func(x *model.Secret) error {
				x.Versions = append(x.Versions, &model.Version{VersionID: fmt.Sprint(i), CreatedDate: base})
				return nil
			})
			if err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	got, _ := s.GetSecretByARN(ctx, "us-east-1", a.ARN)
	if len(got.Versions) != n {
		t.Fatalf("lost updates: %d/%d versions", len(got.Versions), n)
	}
}

// testListMeta: store.ListMeta returns ListSecrets' secrets and order with values stripped,
// and must not strip values from stored state.
func testListMeta(t *testing.T, s store.Store) {
	ctx := context.Background()
	a, b := Full("us-east-1", "a", 1), Full("us-east-1", "b", 2)
	create(t, s, b)
	create(t, s, a)
	l, err := store.ListMeta(ctx, s, "us-east-1")
	if err != nil || len(l) != 2 || l[0].Name != "a" || l[1].Name != "b" {
		t.Fatalf("ListMeta: %v %v", l, err)
	}
	if _, ok := s.(store.MetaLister); ok {
		for _, x := range l {
			for _, v := range x.Versions {
				if v.SecretString != nil || v.SecretBinary != nil {
					t.Fatalf("%s/%s: value copied by ListSecretsMeta", x.Name, v.VersionID)
				}
			}
		}
		want := a.CloneMeta()
		equal(t, l[0], want)
	}
	got, _ := s.GetSecretByARN(ctx, "us-east-1", a.ARN)
	equal(t, got, a)
}
