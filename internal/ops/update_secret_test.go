package ops_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nathabonfim59/segredium/internal/api"
	"github.com/nathabonfim59/segredium/internal/model"
	"github.com/nathabonfim59/segredium/internal/sm"
)

func TestUpdateSecretMetadata(t *testing.T) {
	for _, withValue := range []bool{false, true} {
		t.Run(fmt.Sprint(withValue), func(t *testing.T) {
			d := testDeps()
			in := map[string]any{"Name": "secret", "Description": "old", "KmsKeyId": "alias/old", "Type": "old"}
			if withValue {
				in["SecretString"] = "initial"
				in["ClientRequestToken"] = token1
			}
			created := callOK(t, d, region, "CreateSecret", in)
			before := stored(t, d, "secret")
			d.Clock.(*sm.FakeClock).Advance(time.Hour)
			out := callOK(t, d, region, "UpdateSecret", map[string]any{"SecretId": "secret", "ClientRequestToken": token1, "Description": "new", "KmsKeyId": "alias/new", "Type": "partner"})
			assertJSON(t, out, map[string]any{"ARN": created["ARN"], "Name": "secret"})
			s := stored(t, d, "secret")
			if len(s.Versions) != len(before.Versions) || s.Description != "new" || s.KmsKeyID != "alias/new" || s.Type != "partner" || !s.LastChangedDate.Equal(d.Now()) || !s.CreatedDate.Equal(before.CreatedDate) {
				t.Fatalf("metadata update = %#v", s)
			}
			if withValue && (!reflect.DeepEqual(s.Version(token1).KmsKeyIDs, []string{"alias/old", "alias/new"}) || *s.Version(token1).SecretString != "initial") {
				t.Fatal("KMS update changed payload or failed to update current key")
			}
			callOK(t, d, region, "UpdateSecret", map[string]any{"SecretId": "secret", "Description": "", "KmsKeyId": "", "Type": ""})
			s = stored(t, d, "secret")
			if s.Description != "" || s.KmsKeyID != "" || s.Type != "" {
				t.Fatal("explicit empty metadata did not clear fields")
			}
			if withValue && !reflect.DeepEqual(s.Version(token1).KmsKeyIDs, []string{"alias/old", "alias/new", model.DefaultKMSKeyID}) {
				t.Fatal("empty KMS key did not restore default")
			}
			before = s.Clone()
			d.Clock.(*sm.FakeClock).Advance(time.Hour)
			callOK(t, d, region, "UpdateSecret", map[string]any{"SecretId": "secret", "ClientRequestToken": token2})
			callOK(t, d, region, "UpdateSecret", map[string]any{"SecretId": "secret", "Description": "", "KmsKeyId": "", "Type": ""})
			if !reflect.DeepEqual(before, stored(t, d, "secret")) {
				t.Fatal("unchanged metadata request mutated secret")
			}
		})
	}
}

func TestUpdateSecretKMSHistory(t *testing.T) {
	d := testDeps()
	created := callOK(t, d, region, "CreateSecret", `{"Name":"secret","SecretString":"initial","KmsKeyId":"alias/first"}`)
	stages := [][]string{{model.StageCurrent}, {model.StagePrevious}, {model.StagePending}, {"custom"}, nil}
	_, err := d.Store.UpdateSecret(context.Background(), region, created["ARN"].(string), func(s *model.Secret) error {
		s.Versions = nil
		for i, labels := range stages {
			value := fmt.Sprintf("value-%d", i)
			s.Versions = append(s.Versions, &model.Version{
				VersionID: fmt.Sprintf("%032d", i), SecretString: &value,
				Stages: labels, CreatedDate: d.Now(), KmsKeyIDs: []string{"alias/first"},
			})
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"alias/second", "alias/second", "alias/first", "alias/third"} {
		callOK(t, d, region, "UpdateSecret", map[string]any{"SecretId": "secret", "KmsKeyId": key})
	}
	s := stored(t, d, "secret")
	for i, v := range s.Versions {
		want := []string{"alias/first"}
		if i < 3 {
			want = []string{"alias/first", "alias/second", "alias/third"}
		}
		if !reflect.DeepEqual(v.KmsKeyIDs, want) {
			t.Errorf("version %d key history = %v, want %v", i, v.KmsKeyIDs, want)
		}
		if *v.SecretString != fmt.Sprintf("value-%d", i) || !reflect.DeepEqual(v.Stages, stages[i]) {
			t.Errorf("key update changed version %d payload or labels", i)
		}
	}
	// New values use just the currently selected key; history belongs to the
	// previously encrypted versions, not to the newly created version.
	out := callOK(t, d, region, "UpdateSecret", `{"SecretId":"secret","SecretString":"new"}`)
	if keys := stored(t, d, "secret").Version(out["VersionId"].(string)).KmsKeyIDs; !reflect.DeepEqual(keys, []string{"alias/third"}) {
		t.Fatalf("new version keys = %v", keys)
	}
}

func TestUpdateSecretValuesAndIdempotency(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value map[string]any
	}{
		{"string", map[string]any{"SecretString": "next"}},
		{"binary", map[string]any{"SecretBinary": []byte{0, 255, 128}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := testDeps()
			created := create(t, d, "secret")
			d.Clock.(*sm.FakeClock).Advance(time.Hour)
			in := map[string]any{"SecretId": created["ARN"], "ClientRequestToken": token2, "Description": "updated", "KmsKeyId": "alias/new", "Type": "partner"}
			for k, v := range tc.value {
				in[k] = v
			}
			out := callOK(t, d, region, "UpdateSecret", in)
			assertJSON(t, out, map[string]any{"ARN": created["ARN"], "Name": "secret", "VersionId": token2})
			s := stored(t, d, "secret")
			v := s.Version(token2)
			if len(s.Versions) != 2 || !s.Version(token1).HasStage(model.StagePrevious) || s.Version(token1).HasStage(model.StageCurrent) || !v.HasStage(model.StageCurrent) || !v.CreatedDate.Equal(d.Now()) || !s.LastChangedDate.Equal(d.Now()) || !reflect.DeepEqual(v.KmsKeyIDs, []string{"alias/new"}) {
				t.Fatalf("new version = %#v", s)
			}
			got := callOK(t, d, region, "GetSecretValue", map[string]any{"SecretId": "secret"})
			for member, value := range tc.value {
				if binary, ok := value.([]byte); ok {
					if got[member] != "AP+A" || !bytes.Equal(v.SecretBinary, binary) || v.SecretString != nil {
						t.Fatal("binary value did not round trip")
					}
				} else if got[member] != value || v.SecretBinary != nil {
					t.Fatal("string value did not round trip")
				}
			}
			before := stored(t, d, "secret")
			d.Clock.(*sm.FakeClock).Advance(time.Hour)
			in["Description"] = "ignored"
			assertJSON(t, callOK(t, d, region, "UpdateSecret", in), out)
			assertJSON(t, callOK(t, d, region, "UpdateSecret", map[string]any{"SecretId": "secret", "ClientRequestToken": token1, "SecretString": "initial"}), map[string]any{"ARN": created["ARN"], "Name": "secret", "VersionId": token1})
			if !reflect.DeepEqual(before, stored(t, d, "secret")) {
				t.Fatal("retry changed secret or stages")
			}
			callError(t, d, "UpdateSecret", map[string]any{"SecretId": "secret", "ClientRequestToken": token2, "SecretString": "conflict", "Description": "rejected"}, "ResourceExistsException", "You can't use the currently specified client request token because a version with the same token but a different secret value already exists.")
			if !reflect.DeepEqual(before, stored(t, d, "secret")) {
				t.Fatal("token conflict changed metadata")
			}
		})
	}
}

func TestUpdateSecretFirstValueGeneratedToken(t *testing.T) {
	d := testDeps()
	created := callOK(t, d, region, "CreateSecret", `{"Name":"secret"}`)
	// The HTTP shell consumes 16 bytes for the request ID before the handler.
	d.Rand = bytes.NewReader(make([]byte, 32))
	out := callOK(t, d, region, "UpdateSecret", `{"SecretId":"secret","SecretString":"first","Unknown":true}`)
	assertJSON(t, out, map[string]any{"ARN": created["ARN"], "Name": "secret", "VersionId": "00000000-0000-4000-8000-000000000000"})
	s := stored(t, d, "secret")
	if len(s.Versions) != 1 || !s.Versions[0].HasStage(model.StageCurrent) || !reflect.DeepEqual(s.Versions[0].KmsKeyIDs, []string{model.DefaultKMSKeyID}) {
		t.Fatal("first value did not receive current stage/default key")
	}
	// Metadata-only calls must neither need randomness nor create another version.
	d.Rand = bytes.NewReader(nil)
	callOK(t, d, region, "UpdateSecret", `{"SecretId":"secret","Description":"metadata"}`)
}

func TestUpdateSecretValidation(t *testing.T) {
	for _, tc := range []struct{ name, input, code, message string }{
		{"missing id", `{}`, "ValidationException", "1 validation error detected: Value null at 'secretId' failed to satisfy constraint: Member must not be null"},
		{"null id", `{"SecretId":null}`, "ValidationException", ""},
		{"empty id", `{"SecretId":""}`, "ValidationException", ""},
		{"both values", `{"SecretId":"secret","SecretString":"x","SecretBinary":"eA=="}`, "InvalidParameterException", "You can't specify both SecretBinary and SecretString."},
		{"empty string", `{"SecretId":"secret","SecretString":""}`, "ValidationException", ""},
		{"empty binary", `{"SecretId":"secret","SecretBinary":""}`, "ValidationException", ""},
		{"short token", `{"SecretId":"secret","ClientRequestToken":"short"}`, "ValidationException", ""},
		{"malformed binary", `{"SecretId":"secret","SecretBinary":"!"}`, "SerializationException", ""},
		{"wrong type", `{"SecretId":123}`, "SerializationException", ""},
		{"missing secret", `{"SecretId":"missing"}`, "ResourceNotFoundException", sm.MsgNotFound},
	} {
		t.Run(tc.name, func(t *testing.T) { callError(t, testDeps(), "UpdateSecret", tc.input, tc.code, tc.message) })
	}
	for _, tc := range []struct {
		member string
		size   int
	}{{"SecretId", 2049}, {"ClientRequestToken", 65}, {"Description", 2049}, {"KmsKeyId", 2049}, {"Type", 257}, {"SecretString", 65537}, {"SecretBinary", 65537}} {
		t.Run(tc.member+" max", func(t *testing.T) {
			in := map[string]any{"SecretId": "secret", tc.member: strings.Repeat("x", tc.size)}
			if tc.member == "SecretBinary" {
				in[tc.member] = make([]byte, tc.size)
			}
			callError(t, testDeps(), "UpdateSecret", in, "ValidationException", "")
		})
	}
	d := testDeps()
	var logs bytes.Buffer
	d.Log = slog.New(slog.NewTextHandler(&logs, nil))
	status, body := api.TestCall(d, region, "UpdateSecret", map[string]any{"SecretId": "secret", "SecretString": strings.Repeat("private-", 9000)})
	if status != 400 || api.ErrorType(body) != "ValidationException" || bytes.Contains(body, []byte("private-")) || strings.Contains(logs.String(), "private-") {
		t.Fatalf("sensitive validation: %d %s", status, body)
	}
}

func TestUpdateSecretStateAndRegion(t *testing.T) {
	for _, tc := range []struct {
		name, message string
		mutate        func(*model.Secret)
	}{
		{"deleted", "You can't perform this operation on the secret because it was marked for deletion.", func(s *model.Secret) { now := time.Date(2026, 11, 6, 0, 0, 0, 0, time.UTC); s.DeletedDate = &now }},
		{"replica", "Operation not permitted on a replica secret. Call must be made in primary secret's region.", func(s *model.Secret) { s.IsReplica = true; s.PrimaryRegion = "us-west-2" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := testDeps()
			created := create(t, d, "secret")
			_, err := d.Store.UpdateSecret(context.Background(), region, created["ARN"].(string), func(s *model.Secret) error { tc.mutate(s); return nil })
			if err != nil {
				t.Fatal(err)
			}
			before := stored(t, d, "secret")
			for _, in := range []any{`{"SecretId":"secret","Description":"new"}`, map[string]any{"SecretId": "secret", "ClientRequestToken": token1, "SecretString": "initial"}} {
				callError(t, d, "UpdateSecret", in, "InvalidRequestException", tc.message)
			}
			if !reflect.DeepEqual(before, stored(t, d, "secret")) {
				t.Fatal("rejected update mutated secret")
			}
		})
	}
	d := testDeps()
	created := create(t, d, "secret")
	for _, id := range []string{"secret", created["ARN"].(string)} {
		status, body := api.TestCall(d, "us-west-2", "UpdateSecret", map[string]any{"SecretId": id, "Description": "wrong region"})
		if status != 400 || api.ErrorType(body) != "ResourceNotFoundException" {
			t.Fatalf("wrong region: %d %s", status, body)
		}
	}
	arn := created["ARN"].(string)
	partial := arn[:len(arn)-7]
	callOK(t, d, region, "UpdateSecret", map[string]any{"SecretId": partial, "Description": "partial ARN"})
	if stored(t, d, "secret").Description != "partial ARN" {
		t.Fatal("partial ARN failed")
	}
}

func TestUpdateSecretOwnerAccess(t *testing.T) {
	owner, other, root := uint32(1000), uint32(1001), uint32(0)
	for _, mode := range []string{"machine", "owner"} {
		for _, uid := range []*uint32{nil, &other, &owner, &root} {
			d := testDeps()
			created := create(t, d, "secret")
			d.Config.Server.AccessMode = mode
			_, err := d.Store.UpdateSecret(context.Background(), region, created["ARN"].(string), func(s *model.Secret) error { s.OwnerUID = &owner; return nil })
			if err != nil {
				t.Fatal(err)
			}
			before := stored(t, d, "secret")
			r := httptest.NewRequest("POST", "/", strings.NewReader(`{"SecretId":"secret","Description":"new"}`))
			r.Header.Set("X-Amz-Target", api.TargetPrefix+"UpdateSecret")
			w := httptest.NewRecorder()
			api.NewServer(d, uidAuth{uid}).ServeHTTP(w, r)
			if mode == "owner" && (uid == nil || *uid == other) {
				if w.Code != 400 || api.ErrorType(w.Body.Bytes()) != "AccessDeniedException" || !strings.Contains(w.Body.String(), "secretsmanager:UpdateSecret") {
					t.Fatalf("denied update: %d %s", w.Code, w.Body.String())
				}
				if !reflect.DeepEqual(before, stored(t, d, "secret")) {
					t.Fatal("unauthorized update mutated secret")
				}
			} else if w.Code != 200 {
				t.Fatalf("allowed update: %d %s", w.Code, w.Body.String())
			}
		}
	}
}

func TestUpdateSecretRetentionAndRollback(t *testing.T) {
	for _, age := range []time.Duration{time.Hour, 24 * time.Hour} {
		t.Run(age.String(), func(t *testing.T) {
			d := testDeps()
			created := create(t, d, "secret")
			_, err := d.Store.UpdateSecret(context.Background(), region, created["ARN"].(string), func(s *model.Secret) error {
				for i := range 99 {
					s.Versions = append(s.Versions, &model.Version{VersionID: fmt.Sprintf("%032d", i), SecretString: s.Versions[0].SecretString, CreatedDate: d.Now().Add(-age)})
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			before := stored(t, d, "secret")
			in := map[string]any{"SecretId": "secret", "ClientRequestToken": token2, "SecretString": "next", "Description": "new", "KmsKeyId": "alias/new"}
			if age < 24*time.Hour {
				callError(t, d, "UpdateSecret", in, "LimitExceededException", "You exceeded the maximum number of versions for a secret. Remove staging labels from older versions to allow Secrets Manager to delete them.")
				if !reflect.DeepEqual(before, stored(t, d, "secret")) {
					t.Fatal("quota rejection changed metadata or versions")
				}
				return
			}
			callOK(t, d, region, "UpdateSecret", in)
			s := stored(t, d, "secret")
			if len(s.Versions) != 100 || s.Version(fmt.Sprintf("%032d", 0)) != nil || s.Version(token2) == nil || !s.Version(token1).HasStage(model.StagePrevious) {
				t.Fatal("retention failed")
			}
		})
	}
}

func TestUpdateSecretReplication(t *testing.T) {
	d := testDeps()
	rep := &recordingReplicator{store: d, syncError: errors.New("replication unavailable")}
	d.Replicator = rep
	callOK(t, d, region, "CreateSecret", `{"Name":"secret","SecretString":"initial","AddReplicaRegions":[{"Region":"us-west-2"}]}`)
	in := map[string]any{"SecretId": "secret", "ClientRequestToken": token2, "SecretString": "next"}
	callOK(t, d, region, "UpdateSecret", in)
	callOK(t, d, region, "UpdateSecret", in)
	callOK(t, d, region, "UpdateSecret", `{"SecretId":"secret","Description":"new"}`)
	callOK(t, d, region, "UpdateSecret", `{"SecretId":"secret","Description":"new"}`)
	if rep.syncCalls != 2 {
		t.Fatalf("Sync called %d times, want 2 writes", rep.syncCalls)
	}
}

func TestUpdateSecretConcurrentRetry(t *testing.T) {
	d := testDeps()
	create(t, d, "secret")
	type updateResult struct {
		status int
		body   []byte
	}
	results := make(chan updateResult, 12)
	var wg sync.WaitGroup
	for range 12 {
		wg.Go(func() {
			status, body := api.TestCall(d, region, "UpdateSecret", map[string]any{"SecretId": "secret", "ClientRequestToken": token2, "SecretString": "next"})
			results <- updateResult{status, body}
		})
	}
	wg.Wait()
	close(results)
	for result := range results {
		if result.status != 200 {
			t.Fatalf("concurrent retry: %d %s", result.status, result.body)
		}
	}
	s := stored(t, d, "secret")
	if len(s.Versions) != 2 || !s.Version(token2).HasStage(model.StageCurrent) || !s.Version(token1).HasStage(model.StagePrevious) {
		t.Fatal("concurrent retries duplicated version or stages")
	}
}
