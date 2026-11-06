package ops_test

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nathabonfim59/segredium/internal/api"
	"github.com/nathabonfim59/segredium/internal/model"
	"github.com/nathabonfim59/segredium/internal/sm"
	"github.com/nathabonfim59/segredium/internal/store"
	"github.com/nathabonfim59/segredium/internal/store/filestore"
)

func TestDeleteSecretWindow(t *testing.T) {
	for _, days := range []int{0, 7, 30} {
		t.Run(fmt.Sprintf("%d-days", days), func(t *testing.T) {
			d := testDeps()
			created := create(t, d, "secret")
			before := stored(t, d, "secret")
			in := map[string]any{"SecretId": created["ARN"]}
			window := days
			if days == 0 {
				window = 30
			} else {
				in["RecoveryWindowInDays"] = days
			}
			now := d.Now()
			deadline := now.Add(time.Duration(window) * 24 * time.Hour)
			assertJSON(t, callOK(t, d, region, "DeleteSecret", in), map[string]any{"ARN": created["ARN"], "Name": "secret", "DeletionDate": float64(deadline.UnixMilli()) / 1000})
			s := stored(t, d, "secret")
			if s.DeletedDate == nil || !s.DeletedDate.Equal(now) || s.DeletionDate == nil || !s.DeletionDate.Equal(deadline) {
				t.Fatalf("deletion timestamps: %+v", s)
			}
			s.DeletedDate, s.DeletionDate = nil, nil
			if !reflect.DeepEqual(s, before) {
				t.Fatal("scheduling changed unrelated metadata or values")
			}
			callError(t, d, "GetSecretValue", `{"SecretId":"secret"}`, "InvalidRequestException", "You can't perform this operation on the secret because it was marked for deletion.")
			callError(t, d, "CreateSecret", `{"Name":"secret"}`, "InvalidRequestException", "")
			callError(t, d, "DeleteSecret", in, "InvalidRequestException", "You can't perform this operation on the secret because it was marked for deletion.")
			if !stored(t, d, "secret").DeletionDate.Equal(deadline) {
				t.Fatal("repeat delete moved the deadline")
			}
			out := callOK(t, d, region, "ListSecrets", `{}`)
			if len(out["SecretList"].([]any)) != 0 {
				t.Fatal("scheduled secret was listed by default")
			}
			out = callOK(t, d, region, "ListSecrets", `{"IncludePlannedDeletion":true}`)
			if len(out["SecretList"].([]any)) != 1 {
				t.Fatal("scheduled secret missing from planned-deletion list")
			}
		})
	}
}

func TestDeleteSecretForce(t *testing.T) {
	for _, scheduled := range []bool{false, true} {
		t.Run(map[bool]string{false: "active", true: "scheduled"}[scheduled], func(t *testing.T) {
			d := testDeps()
			created := create(t, d, "secret")
			if scheduled {
				callOK(t, d, region, "DeleteSecret", `{"SecretId":"secret"}`)
			}
			in := map[string]any{"SecretId": created["ARN"], "ForceDeleteWithoutRecovery": true}
			assertJSON(t, callOK(t, d, region, "DeleteSecret", in), map[string]any{"ARN": created["ARN"], "Name": "secret", "DeletionDate": float64(d.Now().UnixMilli()) / 1000})
			if _, err := d.Store.GetSecretByName(context.Background(), region, "secret"); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("force delete: %v", err)
			}
			assertJSON(t, callOK(t, d, region, "DeleteSecret", in), map[string]any{})
			callError(t, d, "RestoreSecret", `{"SecretId":"secret"}`, "ResourceNotFoundException", sm.MsgNotFound)
			create(t, d, "secret")
		})
	}
	assertJSON(t, callOK(t, testDeps(), region, "DeleteSecret", `{"SecretId":"missing","ForceDeleteWithoutRecovery":true}`), map[string]any{})
}

func TestDeleteSecretFalseForceWithWindow(t *testing.T) {
	d := testDeps()
	created := create(t, d, "secret")
	deadline := d.Now().Add(7 * 24 * time.Hour)
	assertJSON(t, callOK(t, d, region, "DeleteSecret", map[string]any{
		"SecretId": "secret", "RecoveryWindowInDays": 7, "ForceDeleteWithoutRecovery": false,
	}), map[string]any{"ARN": created["ARN"], "Name": "secret", "DeletionDate": float64(deadline.UnixMilli()) / 1000})
	s := stored(t, d, "secret")
	if !s.Deleted() || s.DeletionDate == nil || !s.DeletionDate.Equal(deadline) {
		t.Fatalf("explicit false must schedule deletion: %+v", s)
	}
}

func TestDeleteSecretValidation(t *testing.T) {
	for _, tc := range []struct{ input, code, message string }{
		{`{}`, "ValidationException", "1 validation error detected: Value null at 'secretId' failed to satisfy constraint: Member must not be null"},
		{`{"SecretId":null}`, "ValidationException", ""},
		{`{"SecretId":""}`, "ValidationException", ""},
		{`{"SecretId":"missing"}`, "ResourceNotFoundException", sm.MsgNotFound},
		{`{"SecretId":"missing","ForceDeleteWithoutRecovery":false}`, "ResourceNotFoundException", sm.MsgNotFound},
		{`{"SecretId":"missing","RecoveryWindowInDays":6}`, "InvalidParameterException", "The RecoveryWindowInDays value must be between 7 and 30 days (inclusive)."},
		{`{"SecretId":"missing","RecoveryWindowInDays":31}`, "InvalidParameterException", "The RecoveryWindowInDays value must be between 7 and 30 days (inclusive)."},
		{`{"SecretId":"missing","RecoveryWindowInDays":0}`, "InvalidParameterException", ""},
		{`{"SecretId":"missing","RecoveryWindowInDays":7,"ForceDeleteWithoutRecovery":true}`, "InvalidParameterException", "You can't use ForceDeleteWithoutRecovery in conjunction with RecoveryWindowInDays."},
		{`{"SecretId":"missing","RecoveryWindowInDays":7,"ForceDeleteWithoutRecovery":false}`, "ResourceNotFoundException", sm.MsgNotFound},
		{`{"SecretId":"missing","RecoveryWindowInDays":7.5}`, "SerializationException", ""},
		{`{"SecretId":"missing","ForceDeleteWithoutRecovery":"true"}`, "SerializationException", ""},
	} {
		t.Run(tc.input, func(t *testing.T) { callError(t, testDeps(), "DeleteSecret", tc.input, tc.code, tc.message) })
	}
	callError(t, testDeps(), "DeleteSecret", map[string]any{"SecretId": strings.Repeat("x", 2049)}, "ValidationException", "")
}

func TestDeleteSecretReplication(t *testing.T) {
	for _, replica := range []bool{false, true} {
		for _, force := range []bool{false, true} {
			d := testDeps()
			created := create(t, d, "secret")
			_, err := d.Store.UpdateSecret(context.Background(), region, created["ARN"].(string), func(s *model.Secret) error {
				if replica {
					s.IsReplica = true
					s.PrimaryRegion = "us-west-2"
				} else {
					s.Replicas = []model.ReplicationStatus{{Region: "us-west-2", Status: "InSync"}}
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			before := stored(t, d, "secret")
			status, body := api.TestCall(d, region, "DeleteSecret", map[string]any{"SecretId": "secret", "ForceDeleteWithoutRecovery": force})
			if status != 400 || api.ErrorType(body) != "InvalidRequestException" || !strings.Contains(string(body), "RemoveRegionsFromReplication") {
				t.Fatalf("replicated delete: %d %s", status, body)
			}
			if !reflect.DeepEqual(before, stored(t, d, "secret")) {
				t.Fatal("failed delete changed a replicated secret")
			}
		}
	}
}

func TestDeleteSecretRegionAndPartialARN(t *testing.T) {
	d := testDeps()
	created := create(t, d, "secret")
	callOK(t, d, "us-west-2", "CreateSecret", `{"Name":"secret"}`)
	arn := created["ARN"].(string)
	partial := arn[:len(arn)-7]
	callOK(t, d, region, "DeleteSecret", map[string]any{"SecretId": partial, "ForceDeleteWithoutRecovery": true})
	callOK(t, d, "us-west-2", "DescribeSecret", `{"SecretId":"secret"}`)
}

func TestDeleteRestoreSecretFilePersistence(t *testing.T) {
	dir := t.TempDir()
	s, err := filestore.Open(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	d := sm.NewTestDeps(s, sm.NewFakeClock(time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)))
	t.Cleanup(func() { d.Store.Close() })
	reopen := func() {
		t.Helper()
		if err := d.Store.Close(); err != nil {
			t.Fatal(err)
		}
		s, err := filestore.Open(dir, "")
		if err != nil {
			t.Fatal(err)
		}
		d.Store = s
	}
	created := create(t, d, "persisted")
	before := stored(t, d, "persisted")
	callOK(t, d, region, "DeleteSecret", `{"SecretId":"persisted","RecoveryWindowInDays":7}`)
	scheduled := stored(t, d, "persisted")
	reopen()
	if !reflect.DeepEqual(scheduled, stored(t, d, "persisted")) {
		t.Fatal("deletion timestamps did not persist")
	}
	callOK(t, d, region, "RestoreSecret", `{"SecretId":"persisted"}`)
	reopen()
	if !reflect.DeepEqual(before, stored(t, d, "persisted")) {
		t.Fatal("restored secret did not persist")
	}
	callOK(t, d, region, "DeleteSecret", `{"SecretId":"persisted","ForceDeleteWithoutRecovery":true}`)
	files, err := filepath.Glob(filepath.Join(dir, "*.secret"))
	if err != nil || len(files) != 0 {
		t.Fatalf("force delete retained files: %v, error %v", files, err)
	}
	reopen()
	callError(t, d, "DescribeSecret", `{"SecretId":"persisted"}`, "ResourceNotFoundException", sm.MsgNotFound)
	if next := create(t, d, "persisted"); next["ARN"] == created["ARN"] {
		t.Fatal("name reuse retained deleted ARN")
	}
}

func TestDeleteSecretConcurrentSchedule(t *testing.T) {
	d := testDeps()
	create(t, d, "secret")
	const n = 12
	type deleteResult struct {
		status int
		body   []byte
	}
	results := make(chan deleteResult, n)
	var wg sync.WaitGroup
	for range n {
		wg.Go(func() {
			status, body := api.TestCall(d, region, "DeleteSecret", `{"SecretId":"secret","RecoveryWindowInDays":7}`)
			results <- deleteResult{status, body}
		})
	}
	wg.Wait()
	close(results)
	successes := 0
	for result := range results {
		if result.status == 200 {
			successes++
			continue
		}
		if result.status != 400 || api.ErrorType(result.body) != "InvalidRequestException" {
			t.Fatalf("concurrent scheduling: %d %s", result.status, result.body)
		}
	}
	if successes != 1 {
		t.Fatalf("successful schedules=%d, want 1", successes)
	}
}
