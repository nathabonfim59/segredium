package ops_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nathabonfim59/segredium/internal/api"
	"github.com/nathabonfim59/segredium/internal/model"
	"github.com/nathabonfim59/segredium/internal/sm"
)

func TestPutSecretValueStagesAndIdempotency(t *testing.T) {
	d := testDeps()
	created := create(t, d, "secret")
	put := func(token, value string, stages []string) map[string]any {
		in := map[string]any{"SecretId": "secret", "ClientRequestToken": token, "SecretString": value}
		if stages != nil {
			in["VersionStages"] = stages
		}
		return callOK(t, d, region, "PutSecretValue", in)
	}
	assertJSON(t, put(token2, "pending", []string{model.StagePending, "custom"}), map[string]any{"ARN": created["ARN"], "Name": "secret", "VersionId": token2, "VersionStages": []string{model.StagePending, "custom"}})
	if !stored(t, d, "secret").Version(token1).HasStage(model.StageCurrent) {
		t.Fatal("pending moved AWSCURRENT")
	}
	d.Clock.(*sm.FakeClock).Advance(time.Hour)
	assertJSON(t, put(token3, "current", nil), map[string]any{"ARN": created["ARN"], "Name": "secret", "VersionId": token3, "VersionStages": []string{model.StageCurrent}})
	s := stored(t, d, "secret")
	if !s.Version(token1).HasStage(model.StagePrevious) || s.Version(token1).HasStage(model.StageCurrent) {
		t.Fatal("AWSPREVIOUS did not move")
	}
	before := s.Clone()
	d.Clock.(*sm.FakeClock).Advance(time.Hour)
	assertJSON(t, put(token1, "initial", []string{model.StageCurrent}), map[string]any{"ARN": created["ARN"], "Name": "secret", "VersionId": token1, "VersionStages": []string{model.StagePrevious}})
	if !reflect.DeepEqual(before, stored(t, d, "secret")) {
		t.Fatal("idempotent put changed secret")
	}
	callError(t, d, "PutSecretValue", map[string]any{"SecretId": "secret", "ClientRequestToken": token1, "SecretString": "different"}, "ResourceExistsException", "")
}

func TestPutSecretValueMissingPayload(t *testing.T) {
	d := testDeps()
	create(t, d, "secret")
	callError(t, d, "PutSecretValue", `{"SecretId":"secret"}`, "InvalidRequestException", "You must provide either SecretString or SecretBinary.")
}

func TestSecretValueValidationDoesNotExposePayloads(t *testing.T) {
	for _, op := range []string{"CreateSecret", "PutSecretValue"} {
		t.Run(op, func(t *testing.T) {
			d := testDeps()
			var logs bytes.Buffer
			d.Log = slog.New(slog.NewTextHandler(&logs, nil))
			secret := strings.Repeat("sensitive-value-", 4500)
			status, body := api.TestCall(d, region, op, map[string]any{"Name": "secret", "SecretId": "secret", "SecretString": secret})
			if status != 400 || api.ErrorType(body) != "ValidationException" {
				t.Fatalf("unexpected response: %d %s", status, body)
			}
			if bytes.Contains(body, []byte("sensitive-value-")) || strings.Contains(logs.String(), "sensitive-value-") {
				t.Fatal("validation echoed SecretString in the error or request log")
			}
		})
	}
	t.Run("RotationToken", func(t *testing.T) {
		d := testDeps()
		var logs bytes.Buffer
		d.Log = slog.New(slog.NewTextHandler(&logs, nil))
		secret := strings.Repeat("private!", 5)
		status, body := api.TestCall(d, region, "PutSecretValue", map[string]any{"SecretId": "secret", "SecretString": "value", "RotationToken": secret})
		if status != 400 || api.ErrorType(body) != "ValidationException" {
			t.Fatalf("unexpected response: %d %s", status, body)
		}
		if bytes.Contains(body, []byte(secret)) || strings.Contains(logs.String(), secret) {
			t.Fatal("validation echoed RotationToken in the error or request log")
		}
	})
}

func TestPutSecretValueReplica(t *testing.T) {
	d := testDeps()
	created := create(t, d, "secret")
	_, err := d.Store.UpdateSecret(context.Background(), region, created["ARN"].(string), func(s *model.Secret) error { s.IsReplica = true; s.PrimaryRegion = "us-west-2"; return nil })
	if err != nil {
		t.Fatal(err)
	}
	callError(t, d, "PutSecretValue", `{"SecretId":"secret","SecretString":"value"}`, "InvalidRequestException", "Operation not permitted on a replica secret. Call must be made in primary secret's region.")
	if len(stored(t, d, "secret").Versions) != 1 {
		t.Fatal("replica mutation stored a version")
	}
}

func TestPutSecretValueValidation(t *testing.T) {
	for _, tc := range []struct{ name, input, code, message string }{
		{"missing id", `{}`, "ValidationException", "1 validation error detected: Value null at 'secretId' failed to satisfy constraint: Member must not be null"},
		{"both values", `{"SecretId":"secret","SecretString":"x","SecretBinary":"eA=="}`, "InvalidParameterException", "You can't specify both SecretBinary and SecretString."},
		{"empty string", `{"SecretId":"secret","SecretString":""}`, "ValidationException", ""},
		{"empty binary", `{"SecretId":"secret","SecretBinary":""}`, "ValidationException", ""},
		{"short token", `{"SecretId":"secret","SecretString":"x","ClientRequestToken":"x"}`, "ValidationException", ""},
		{"empty stages", `{"SecretId":"secret","SecretString":"x","VersionStages":[]}`, "ValidationException", ""},
		{"null stage", `{"SecretId":"secret","SecretString":"x","VersionStages":[null]}`, "ValidationException", ""},
		{"empty stage", `{"SecretId":"secret","SecretString":"x","VersionStages":[""]}`, "ValidationException", ""},
		{"short rotation token", `{"SecretId":"secret","SecretString":"x","RotationToken":"short"}`, "ValidationException", ""},
		{"unknown secret", `{"SecretId":"missing","SecretString":"x"}`, "ResourceNotFoundException", sm.MsgNotFound},
	} {
		t.Run(tc.name, func(t *testing.T) { callError(t, testDeps(), "PutSecretValue", tc.input, tc.code, tc.message) })
	}
	for _, tc := range []struct {
		member string
		size   int
	}{{"SecretId", 2049}, {"SecretString", 65537}, {"ClientRequestToken", 65}, {"RotationToken", 257}} {
		t.Run(tc.member+" max", func(t *testing.T) {
			callError(t, testDeps(), "PutSecretValue", map[string]any{"SecretId": "secret", "SecretString": "x", tc.member: strings.Repeat("x", tc.size)}, "ValidationException", "")
		})
	}
	d := testDeps()
	create(t, d, "secret")
	callError(t, d, "PutSecretValue", map[string]any{"SecretId": "secret", "SecretString": "x", "RotationToken": strings.Repeat("!", 36)}, "ValidationException", "")
	callError(t, d, "PutSecretValue", map[string]any{"SecretId": "secret", "SecretString": "x", "VersionStages": []string{strings.Repeat("x", 257)}}, "ValidationException", "")
	stages := make([]string, 21)
	for i := range stages {
		stages[i] = fmt.Sprintf("stage-%d", i)
	}
	callError(t, d, "PutSecretValue", map[string]any{"SecretId": "secret", "SecretString": "x", "VersionStages": stages}, "ValidationException", "")
}

func TestPutSecretValueBinaryAndFirstVersion(t *testing.T) {
	d := testDeps()
	created := callOK(t, d, region, "CreateSecret", `{"Name":"secret"}`)
	value := []byte{0, 1, 255}
	out := callOK(t, d, region, "PutSecretValue", map[string]any{"SecretId": created["ARN"], "ClientRequestToken": token1, "SecretBinary": value, "VersionStages": []string{model.StagePending, model.StagePending}, "RotationToken": token2})
	assertJSON(t, out, map[string]any{"ARN": created["ARN"], "Name": "secret", "VersionId": token1, "VersionStages": []string{model.StagePending, model.StageCurrent}})
	before := stored(t, d, "secret")
	callOK(t, d, region, "PutSecretValue", map[string]any{"SecretId": "secret", "ClientRequestToken": token1, "SecretBinary": value, "VersionStages": []string{"ignored"}})
	if !reflect.DeepEqual(before, stored(t, d, "secret")) {
		t.Fatal("binary retry mutated state")
	}
	callError(t, d, "PutSecretValue", map[string]any{"SecretId": "secret", "ClientRequestToken": token1, "SecretString": "AAH/"}, "ResourceExistsException", "")
	callError(t, d, "PutSecretValue", map[string]any{"SecretId": "secret", "ClientRequestToken": token1, "SecretBinary": []byte{0, 1}}, "ResourceExistsException", "")
	got := callOK(t, d, region, "GetSecretValue", `{"SecretId":"secret"}`)
	assertJSON(t, got, map[string]any{"ARN": created["ARN"], "Name": "secret", "VersionId": token1, "SecretBinary": value, "VersionStages": []string{model.StagePending, model.StageCurrent}, "CreatedDate": float64(d.Now().UnixMilli()) / 1000})
}

func TestPutSecretValueMovesLabels(t *testing.T) {
	d := testDeps()
	create(t, d, "secret")
	callOK(t, d, region, "PutSecretValue", map[string]any{"SecretId": "secret", "SecretString": "second", "ClientRequestToken": token2})
	callOK(t, d, region, "PutSecretValue", map[string]any{"SecretId": "secret", "SecretString": "third", "ClientRequestToken": token3})
	s := stored(t, d, "secret")
	if len(s.Version(token1).Stages) != 0 || !s.Version(token2).HasStage(model.StagePrevious) || !s.Version(token3).HasStage(model.StageCurrent) {
		t.Fatal("AWSPREVIOUS remained on older version")
	}
	callOK(t, d, region, "PutSecretValue", map[string]any{"SecretId": "secret", "SecretString": "fourth", "VersionStages": []string{model.StagePrevious, model.StageCurrent, "custom"}})
	s = stored(t, d, "secret")
	if !s.Version(token3).HasStage(model.StagePrevious) || s.VersionByStage(model.StageCurrent).HasStage(model.StagePrevious) {
		t.Fatal("moving AWSCURRENT must assign AWSPREVIOUS to former current")
	}
}

func TestPutSecretValueDeleted(t *testing.T) {
	d := testDeps()
	created := create(t, d, "secret")
	_, err := d.Store.UpdateSecret(context.Background(), region, created["ARN"].(string), func(s *model.Secret) error { now := d.Now(); s.DeletedDate = &now; return nil })
	if err != nil {
		t.Fatal(err)
	}
	callError(t, d, "PutSecretValue", map[string]any{"SecretId": "secret", "SecretString": "initial", "ClientRequestToken": token1}, "InvalidRequestException", "You can't perform this operation on the secret because it was marked for deletion.")
}

func TestPutSecretValueRetention(t *testing.T) {
	for _, tc := range []struct {
		name             string
		age              time.Duration
		labeled, success bool
	}{
		{"recent", time.Hour, false, false},
		{"boundary", 24 * time.Hour, false, true},
		{"old", 48 * time.Hour, false, true},
		{"labeled", 48 * time.Hour, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := testDeps()
			created := create(t, d, "secret")
			_, err := d.Store.UpdateSecret(context.Background(), region, created["ARN"].(string), func(s *model.Secret) error {
				initial := s.Versions[0]
				s.Versions = make([]*model.Version, 0, 100)
				for i := range 99 {
					v := &model.Version{VersionID: fmt.Sprintf("%032d", i), SecretString: initial.SecretString, CreatedDate: d.Now().Add(-tc.age)}
					if tc.labeled {
						if i < 18 {
							v.Stages = []string{fmt.Sprintf("label-%d", i)}
						} else {
							v.CreatedDate = d.Now().Add(-time.Hour)
						}
					}
					s.Versions = append(s.Versions, v)
				}
				s.Versions = append(s.Versions, initial)
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			before := stored(t, d, "secret")
			in := map[string]any{"SecretId": "secret", "SecretString": "new", "ClientRequestToken": token2}
			if !tc.success {
				callError(t, d, "PutSecretValue", in, "LimitExceededException", "You exceeded the maximum number of versions for a secret. Remove staging labels from older versions to allow Secrets Manager to delete them.")
				if !reflect.DeepEqual(before, stored(t, d, "secret")) {
					t.Fatal("quota failure mutated labels or versions")
				}
				return
			}
			callOK(t, d, region, "PutSecretValue", in)
			s := stored(t, d, "secret")
			if len(s.Versions) != 100 || s.Version(fmt.Sprintf("%032d", 0)) != nil || s.Version(token2) == nil || !s.Version(token1).HasStage(model.StagePrevious) {
				t.Fatal("retention did not prune oldest eligible version")
			}
		})
	}
}

func TestPutSecretValueLabelQuota(t *testing.T) {
	d := testDeps()
	create(t, d, "secret")
	stages := make([]string, 20)
	stages[0] = model.StageCurrent
	for i := 1; i < len(stages); i++ {
		stages[i] = fmt.Sprintf("custom-%d", i)
	}
	before := stored(t, d, "secret")
	callError(t, d, "PutSecretValue", map[string]any{"SecretId": "secret", "SecretString": "new", "VersionStages": stages}, "LimitExceededException", "")
	if !reflect.DeepEqual(before, stored(t, d, "secret")) {
		t.Fatal("label quota failure mutated secret")
	}
}

func TestPutSecretValueReplication(t *testing.T) {
	d := testDeps()
	rep := &recordingReplicator{store: d, syncError: errors.New("replication unavailable")}
	d.Replicator = rep
	callOK(t, d, region, "CreateSecret", `{"Name":"secret","SecretString":"initial","AddReplicaRegions":[{"Region":"us-west-2"}]}`)
	in := map[string]any{"SecretId": "secret", "SecretString": "new", "ClientRequestToken": token2}
	callOK(t, d, region, "PutSecretValue", in)
	callOK(t, d, region, "PutSecretValue", in)
	if rep.syncCalls != 1 {
		t.Fatalf("Sync called %d times; retry should not sync", rep.syncCalls)
	}
}

func TestPutSecretValueConcurrent(t *testing.T) {
	d := testDeps()
	create(t, d, "secret")
	const n = 12
	type result struct {
		status int
		body   []byte
	}
	results := make(chan result, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() {
			status, body := api.TestCall(d, region, "PutSecretValue", map[string]any{"SecretId": "secret", "SecretString": "new", "ClientRequestToken": fmt.Sprintf("%032d", i)})
			results <- result{status, body}
		})
	}
	wg.Wait()
	close(results)
	for result := range results {
		if result.status != 200 {
			t.Fatalf("concurrent put: %d %s", result.status, result.body)
		}
	}
	s := stored(t, d, "secret")
	current, previous := 0, 0
	for _, v := range s.Versions {
		if v.HasStage(model.StageCurrent) {
			current++
		}
		if v.HasStage(model.StagePrevious) {
			previous++
		}
	}
	if len(s.Versions) != n+1 || current != 1 || previous != 1 {
		t.Fatalf("lost versions or duplicated labels: %d versions, %d current, %d previous", len(s.Versions), current, previous)
	}
}

func BenchmarkPutSecretValue(b *testing.B) {
	d := testDeps()
	status, body := api.TestCall(d, region, "CreateSecret", `{"Name":"secret","SecretString":"value"}`)
	if status != 200 {
		b.Fatalf("setup: %d %s", status, body)
	}
	clock := d.Clock.(*sm.FakeClock)
	// Keep the store at its retention bound; each new version can deprecate an old one.
	for range 99 {
		clock.Advance(25 * time.Hour)
		api.TestCall(d, region, "PutSecretValue", `{"SecretId":"secret","SecretString":"value"}`)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		clock.Advance(25 * time.Hour)
		status, body := api.TestCall(d, region, "PutSecretValue", `{"SecretId":"secret","SecretString":"value"}`)
		if status != 200 {
			b.Fatalf("put: %d %s", status, body)
		}
	}
}
