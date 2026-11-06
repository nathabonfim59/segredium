package ops_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/nathabonfim59/segredium/internal/api"
	"github.com/nathabonfim59/segredium/internal/model"
	"github.com/nathabonfim59/segredium/internal/sm"
	"github.com/nathabonfim59/segredium/internal/store"
)

func TestGetSecretValueWire(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value map[string]any
	}{
		{"string", map[string]any{"SecretString": "hello"}},
		{"binary", map[string]any{"SecretBinary": []byte{0, 1, 255}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := testDeps()
			in := map[string]any{"Name": "secret", "ClientRequestToken": token1}
			for k, v := range tc.value {
				in[k] = v
			}
			created := callOK(t, d, region, "CreateSecret", in)
			for _, id := range []string{"secret", created["ARN"].(string), "arn:aws:secretsmanager:" + region + ":" + d.AccountID() + ":secret:secret"} {
				out := callOK(t, d, region, "GetSecretValue", map[string]any{"SecretId": id})
				want := map[string]any{"ARN": created["ARN"], "Name": "secret", "VersionId": token1, "CreatedDate": float64(d.Now().UnixMilli()) / 1000, "VersionStages": []string{model.StageCurrent}}
				for k, v := range tc.value {
					want[k] = v
				}
				assertJSON(t, out, want)
			}
		})
	}
}

func TestGetSecretValueSelection(t *testing.T) {
	d := testDeps()
	create(t, d, "secret")
	callOK(t, d, region, "PutSecretValue", map[string]any{"SecretId": "secret", "SecretString": "second", "ClientRequestToken": token2})
	callOK(t, d, region, "PutSecretValue", map[string]any{"SecretId": "secret", "SecretString": "third", "ClientRequestToken": token3})
	for _, tc := range []struct {
		name  string
		extra map[string]any
		id    string
	}{
		{"default", nil, token3},
		{"by id", map[string]any{"VersionId": token1}, token1},
		{"by previous", map[string]any{"VersionStage": model.StagePrevious}, token2},
		{"both", map[string]any{"VersionId": token2, "VersionStage": model.StagePrevious}, token2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := map[string]any{"SecretId": "secret"}
			for k, v := range tc.extra {
				in[k] = v
			}
			out := callOK(t, d, region, "GetSecretValue", in)
			v := stored(t, d, "secret").Version(tc.id)
			want := map[string]any{"ARN": stored(t, d, "secret").ARN, "Name": "secret", "VersionId": tc.id, "SecretString": *v.SecretString, "CreatedDate": float64(v.CreatedDate.UnixMilli()) / 1000}
			if len(v.Stages) > 0 {
				want["VersionStages"] = v.Stages
			}
			assertJSON(t, out, want)
		})
	}
	callError(t, d, "GetSecretValue", map[string]any{"SecretId": "secret", "VersionId": token1, "VersionStage": model.StageCurrent}, "InvalidRequestException", "You provided a VersionStage that is not associated to the provided VersionId.")
	callError(t, d, "GetSecretValue", map[string]any{"SecretId": "secret", "VersionId": strings.Repeat("x", 32)}, "ResourceNotFoundException", "Secrets Manager can't find the specified secret value for VersionId: "+strings.Repeat("x", 32))
	callError(t, d, "GetSecretValue", `{"SecretId":"secret","VersionStage":"missing"}`, "ResourceNotFoundException", "Secrets Manager can't find the specified secret value for staging label: missing")
	status, body := api.TestCall(d, "us-west-2", "GetSecretValue", `{"SecretId":"secret"}`)
	if status != 400 || api.ErrorType(body) != "ResourceNotFoundException" {
		t.Fatalf("region isolation: %d %s", status, body)
	}
}

type countingStore struct {
	store.Store
	updates int
}

func (s *countingStore) UpdateSecret(ctx context.Context, reg, arn string, fn func(*model.Secret) error) (*model.Secret, error) {
	s.updates++
	return s.Store.UpdateSecret(ctx, reg, arn, fn)
}

func TestGetSecretValueAccessDay(t *testing.T) {
	d := testDeps()
	create(t, d, "secret")
	counter := &countingStore{Store: d.Store}
	d.Store = counter
	before := stored(t, d, "secret")
	callOK(t, d, region, "GetSecretValue", `{"SecretId":"secret"}`)
	s := stored(t, d, "secret")
	day := model.Day(d.Now())
	if s.LastAccessedDate == nil || !s.LastAccessedDate.Equal(day) || s.Version(token1).LastAccessedDate == nil || !s.Version(token1).LastAccessedDate.Equal(day) {
		t.Fatal("access date must be UTC day on both secret and version")
	}
	if !s.LastChangedDate.Equal(*before.LastChangedDate) {
		t.Fatal("read changed LastChangedDate")
	}
	d.Clock.(*sm.FakeClock).Advance(time.Hour)
	callOK(t, d, region, "GetSecretValue", `{"SecretId":"secret"}`)
	if counter.updates != 1 {
		t.Fatalf("same-day read made %d writes, want 1 total", counter.updates)
	}
	d.Clock.(*sm.FakeClock).Advance(24 * time.Hour)
	callOK(t, d, region, "GetSecretValue", `{"SecretId":"secret"}`)
	if counter.updates != 2 || !stored(t, d, "secret").LastAccessedDate.Equal(model.Day(d.Now())) {
		t.Fatal("next-day read did not update access date once")
	}
}

func TestGetSecretValueErrors(t *testing.T) {
	d := testDeps()
	for _, tc := range []struct{ name, input, code, message string }{
		{"missing id", `{}`, "ValidationException", "1 validation error detected: Value null at 'secretId' failed to satisfy constraint: Member must not be null"},
		{"empty id", `{"SecretId":""}`, "ValidationException", ""},
		{"short version", `{"SecretId":"secret","VersionId":"short"}`, "ValidationException", ""},
		{"empty stage", `{"SecretId":"secret","VersionStage":""}`, "ValidationException", ""},
		{"unknown secret", `{"SecretId":"missing"}`, "ResourceNotFoundException", sm.MsgNotFound},
		{"wrong account", `{"SecretId":"arn:aws:secretsmanager:us-east-1:999999999999:secret:secret"}`, "ResourceNotFoundException", sm.MsgNotFound},
	} {
		t.Run(tc.name, func(t *testing.T) { callError(t, d, "GetSecretValue", tc.input, tc.code, tc.message) })
	}
	callOK(t, d, region, "CreateSecret", `{"Name":"empty"}`)
	callError(t, d, "GetSecretValue", `{"SecretId":"empty"}`, "ResourceNotFoundException", "Secrets Manager can't find the specified secret value for staging label: AWSCURRENT")
	created := create(t, d, "secret")
	_, err := d.Store.UpdateSecret(context.Background(), region, created["ARN"].(string), func(s *model.Secret) error { now := d.Now(); s.DeletedDate = &now; return nil })
	if err != nil {
		t.Fatal(err)
	}
	callError(t, d, "GetSecretValue", `{"SecretId":"secret"}`, "InvalidRequestException", "You can't perform this operation on the secret because it was marked for deletion.")
	if stored(t, d, "secret").LastAccessedDate != nil {
		t.Fatal("failed get recorded access")
	}
}

func BenchmarkGetSecretValue(b *testing.B) {
	d := testDeps()
	status, body := api.TestCall(d, region, "CreateSecret", `{"Name":"secret","SecretString":"value"}`)
	if status != 200 {
		b.Fatalf("setup: %d %s", status, body)
	}
	api.TestCall(d, region, "GetSecretValue", `{"SecretId":"secret"}`)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		status, body := api.TestCall(d, region, "GetSecretValue", `{"SecretId":"secret"}`)
		if status != 200 {
			b.Fatalf("get: %d %s", status, body)
		}
	}
}
