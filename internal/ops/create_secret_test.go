package ops_test

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nathabonfim59/segredium/internal/api"
	"github.com/nathabonfim59/segredium/internal/model"
	_ "github.com/nathabonfim59/segredium/internal/ops"
	"github.com/nathabonfim59/segredium/internal/sm"
	"github.com/nathabonfim59/segredium/internal/store/memstore"
)

const (
	region = "us-east-1"
	token1 = "11111111-1111-4111-8111-111111111111"
	token2 = "22222222-2222-4222-8222-222222222222"
	token3 = "33333333-3333-4333-8333-333333333333"
)

func testDeps() *sm.Deps {
	return sm.NewTestDeps(memstore.New(), sm.NewFakeClock(time.Date(2026, 11, 6, 13, 14, 15, 123000000, time.UTC)))
}

func callOK(t *testing.T, d *sm.Deps, reg, op string, in any) map[string]any {
	t.Helper()
	status, body := api.TestCall(d, reg, op, in)
	if status != 200 {
		t.Fatalf("%s status %d: %s", op, status, body)
	}
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func callError(t *testing.T, d *sm.Deps, op string, in any, code, message string) {
	t.Helper()
	status, body := api.TestCall(d, region, op, in)
	if status != 400 || api.ErrorType(body) != code {
		t.Fatalf("%s got %d %s; want 400 %s", op, status, body, code)
	}
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 || out["Message"] == nil {
		t.Fatalf("invalid error shape: %s", body)
	}
	if message != "" && out["Message"] != message {
		t.Fatalf("message = %q, want %q", out["Message"], message)
	}
}

func assertJSON(t *testing.T, got map[string]any, want any) {
	t.Helper()
	b, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, decoded) {
		t.Fatalf("JSON = %#v, want %#v", got, decoded)
	}
}

func stored(t *testing.T, d *sm.Deps, name string) *model.Secret {
	t.Helper()
	s, err := d.Store.GetSecretByName(context.Background(), region, name)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func create(t *testing.T, d *sm.Deps, name string) map[string]any {
	t.Helper()
	return callOK(t, d, region, "CreateSecret", map[string]any{"Name": name, "SecretString": "initial", "ClientRequestToken": token1})
}

func TestCreateSecretWire(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value map[string]any
	}{
		{"string", map[string]any{"SecretString": "hello"}},
		{"binary", map[string]any{"SecretBinary": []byte{0, 1, 255}}},
		{"no value", map[string]any{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := testDeps()
			in := map[string]any{"Name": "path/secret_+=.@-abcdef", "ClientRequestToken": token1, "Description": "description", "KmsKeyId": "alias/test", "Tags": []map[string]string{{"Key": "env", "Value": "test"}}}
			for k, v := range tc.value {
				in[k] = v
			}
			out := callOK(t, d, region, "CreateSecret", in)
			s := stored(t, d, in["Name"].(string))
			want := map[string]any{"ARN": s.ARN, "Name": s.Name}
			if len(tc.value) > 0 {
				want["VersionId"] = token1
			}
			assertJSON(t, out, want)
			if s.Description != "description" || s.KmsKeyID != "alias/test" || !reflect.DeepEqual(s.Tags, []model.Tag{{Key: "env", Value: "test"}}) || !s.CreatedDate.Equal(d.Now()) || s.LastChangedDate == nil || !s.LastChangedDate.Equal(d.Now()) {
				t.Fatalf("stored metadata: %#v", s)
			}
			if len(tc.value) == 0 {
				if len(s.Versions) != 0 {
					t.Fatal("no-value create must not create a version")
				}
				return
			}
			v := s.Version(token1)
			if v == nil || !v.HasStage(model.StageCurrent) || !v.CreatedDate.Equal(d.Now()) {
				t.Fatalf("initial version = %#v", v)
			}
		})
	}
}

func TestCreateSecretIdempotency(t *testing.T) {
	d := testDeps()
	first := create(t, d, "secret")
	before := stored(t, d, "secret")
	d.Clock.(*sm.FakeClock).Advance(time.Hour)
	retry := callOK(t, d, region, "CreateSecret", map[string]any{"Name": "secret", "SecretString": "initial", "ClientRequestToken": token1, "Description": "ignored"})
	assertJSON(t, retry, first)
	if !reflect.DeepEqual(before, stored(t, d, "secret")) {
		t.Fatal("retry changed stored secret")
	}
	callError(t, d, "CreateSecret", map[string]any{"Name": "secret", "SecretString": "different", "ClientRequestToken": token1}, "ResourceExistsException", "")
	callError(t, d, "CreateSecret", map[string]any{"Name": "secret", "SecretString": "initial", "ClientRequestToken": token2}, "ResourceExistsException", "The operation failed because the secret secret already exists.")
	callOK(t, d, "us-west-2", "CreateSecret", map[string]any{"Name": "secret", "SecretString": "other region"})
}

func TestCreateSecretValidation(t *testing.T) {
	for _, tc := range []struct {
		name, input, code, message string
	}{
		{"missing name", `{}`, "ValidationException", "1 validation error detected: Value null at 'name' failed to satisfy constraint: Member must not be null"},
		{"null name", `{"Name":null}`, "ValidationException", "1 validation error detected: Value null at 'name' failed to satisfy constraint: Member must not be null"},
		{"empty name", `{"Name":""}`, "ValidationException", "1 validation error detected: Value '' at 'name' failed to satisfy constraint: Member must have length greater than or equal to 1"},
		{"invalid name", `{"Name":"bad name"}`, "InvalidParameterException", "Invalid name. Must be a valid name containing alphanumeric characters, or any of the following: -/_+=.@!"},
		{"unicode name", `{"Name":"caf\u00e9"}`, "InvalidParameterException", ""},
		{"both values", `{"Name":"secret","SecretString":"x","SecretBinary":"eA=="}`, "InvalidParameterException", "You can't specify both SecretBinary and SecretString."},
		{"empty string", `{"Name":"secret","SecretString":""}`, "ValidationException", ""},
		{"empty binary", `{"Name":"secret","SecretBinary":""}`, "ValidationException", ""},
		{"short token", `{"Name":"secret","ClientRequestToken":"short"}`, "ValidationException", ""},
		{"null tag", `{"Name":"secret","Tags":[null]}`, "ValidationException", ""},
		{"empty tag key", `{"Name":"secret","Tags":[{"Key":""}]}`, "ValidationException", ""},
		{"missing tag key", `{"Name":"secret","Tags":[{}]}`, "InvalidParameterException", ""},
		{"reserved tag", `{"Name":"secret","Tags":[{"Key":"aws:reserved"}]}`, "InvalidParameterException", ""},
		{"empty replicas", `{"Name":"secret","AddReplicaRegions":[]}`, "ValidationException", ""},
		{"null replica", `{"Name":"secret","AddReplicaRegions":[null]}`, "ValidationException", ""},
		{"missing replica region", `{"Name":"secret","AddReplicaRegions":[{}]}`, "InvalidParameterException", ""},
		{"replica region pattern", `{"Name":"secret","AddReplicaRegions":[{"Region":"bad"}]}`, "ValidationException", ""},
		{"name wrong type", `{"Name":123}`, "SerializationException", "Start of structure or map found where not expected"},
		{"malformed base64", `{"Name":"secret","SecretBinary":"!"}`, "SerializationException", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := testDeps()
			callError(t, d, "CreateSecret", tc.input, tc.code, tc.message)
			secrets, err := d.Store.ListSecrets(context.Background(), region)
			if err != nil || len(secrets) != 0 {
				t.Fatalf("invalid create stored data: %v %v", secrets, err)
			}
		})
	}
	for _, tc := range []struct {
		member string
		size   int
	}{{"Name", 513}, {"Description", 2049}, {"KmsKeyId", 2049}, {"ClientRequestToken", 65}, {"SecretString", 65537}} {
		t.Run(tc.member+" max", func(t *testing.T) {
			in := map[string]any{"Name": "secret", tc.member: strings.Repeat("x", tc.size)}
			callError(t, testDeps(), "CreateSecret", in, "ValidationException", "")
		})
	}
	for _, n := range []int{1, 512} {
		callOK(t, testDeps(), region, "CreateSecret", map[string]any{"Name": strings.Repeat("a", n)})
	}
	for _, n := range []int{32, 64} {
		callOK(t, testDeps(), region, "CreateSecret", map[string]any{"Name": "secret", "ClientRequestToken": strings.Repeat("!", n), "SecretString": "x"})
	}
}

func TestCreateSecretDeleted(t *testing.T) {
	d := testDeps()
	created := create(t, d, "secret")
	_, err := d.Store.UpdateSecret(context.Background(), region, created["ARN"].(string), func(s *model.Secret) error { now := d.Now(); s.DeletedDate = &now; return nil })
	if err != nil {
		t.Fatal(err)
	}
	callError(t, d, "CreateSecret", map[string]any{"Name": "secret", "ClientRequestToken": token1, "SecretString": "initial"}, "InvalidRequestException", "You can't create this secret because a secret with this name is already scheduled for deletion.")
}

func TestCreateSecretGeneratedUUIDAndUnknownMembers(t *testing.T) {
	d := testDeps()
	out := callOK(t, d, region, "CreateSecret", `{"Name":"secret","SecretString":"hello","Unknown":true}`)
	id, ok := out["VersionId"].(string)
	if !ok || len(id) != 36 || id[14] != '4' {
		t.Fatalf("generated VersionId = %v", out["VersionId"])
	}
	if stored(t, d, "secret").Version(id) == nil {
		t.Fatal("generated version not stored")
	}
}

func TestCreateSecretConcurrentRetry(t *testing.T) {
	d := testDeps()
	const n = 12
	type result struct {
		status int
		body   []byte
	}
	results := make(chan result, n)
	var wg sync.WaitGroup
	for range n {
		wg.Go(func() {
			status, body := api.TestCall(d, region, "CreateSecret", map[string]any{"Name": "secret", "ClientRequestToken": token1, "SecretString": "same"})
			results <- result{status, body}
		})
	}
	wg.Wait()
	close(results)
	var first map[string]any
	for result := range results {
		if result.status != 200 {
			t.Fatalf("concurrent create: %d %s", result.status, result.body)
		}
		var out map[string]any
		if err := json.Unmarshal(result.body, &out); err != nil {
			t.Fatal(err)
		}
		if first == nil {
			first = out
		} else {
			assertJSON(t, out, first)
		}
	}
	if len(stored(t, d, "secret").Versions) != 1 {
		t.Fatal("concurrent create duplicated versions")
	}
}

type recordingReplicator struct {
	store               *sm.Deps
	addCalls, syncCalls int
	region, arn         string
	add                 []sm.ReplicaRegion
	force               bool
	syncError           error
}

func (rep *recordingReplicator) AddReplicas(ctx context.Context, reg, arn string, add []sm.ReplicaRegion, force bool) (*model.Secret, []model.ReplicationStatus, error) {
	rep.addCalls++
	rep.region, rep.arn, rep.add, rep.force = reg, arn, add, force
	s, err := rep.store.Store.UpdateSecret(ctx, reg, arn, func(s *model.Secret) error {
		day := model.Day(rep.store.Now())
		s.Replicas = []model.ReplicationStatus{{Region: add[0].Region, KmsKeyID: add[0].KmsKeyID, Status: "InSync", LastAccessedDate: &day}}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	return s, s.Replicas, nil
}

func (rep *recordingReplicator) Sync(_ context.Context, s *model.Secret) error {
	rep.syncCalls++
	if s.VersionByStage(model.StageCurrent) == nil {
		panic("replication called before storing value")
	}
	return rep.syncError
}

func TestCreateSecretReplication(t *testing.T) {
	d := testDeps()
	rep := &recordingReplicator{store: d}
	d.Replicator = rep
	out := callOK(t, d, region, "CreateSecret", map[string]any{"Name": "secret", "SecretString": "value", "ClientRequestToken": token1, "AddReplicaRegions": []map[string]any{{"Region": "us-west-2", "KmsKeyId": "alias/replica"}}, "ForceOverwriteReplicaSecret": true})
	assertJSON(t, out, map[string]any{"ARN": rep.arn, "Name": "secret", "VersionId": token1, "ReplicationStatus": []map[string]any{{"Region": "us-west-2", "KmsKeyId": "alias/replica", "Status": "InSync", "LastAccessedDate": model.Day(d.Now()).Unix()}}})
	if rep.addCalls != 1 || rep.region != region || !rep.force || !reflect.DeepEqual(rep.add, []sm.ReplicaRegion{{Region: "us-west-2", KmsKeyID: "alias/replica"}}) {
		t.Fatalf("replication call: %#v", rep)
	}
	other := testDeps()
	callError(t, other, "CreateSecret", `{"Name":"secret","AddReplicaRegions":[{"Region":"us-west-2"}]}`, "InvalidRequestException", "Replication is not enabled on this server.")
	if stored(t, other, "secret").Name != "secret" {
		t.Fatal("replication must run after storing primary")
	}
}
