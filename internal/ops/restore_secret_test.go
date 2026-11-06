package ops_test

import (
	"bytes"
	"context"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/nathabonfim59/segredium/internal/api"
	"github.com/nathabonfim59/segredium/internal/model"
	"github.com/nathabonfim59/segredium/internal/sm"
	"github.com/nathabonfim59/segredium/internal/store"
)

func TestRestoreSecret(t *testing.T) {
	d := testDeps()
	created := create(t, d, "secret")
	before := stored(t, d, "secret")
	callOK(t, d, region, "DeleteSecret", `{"SecretId":"secret","RecoveryWindowInDays":7}`)
	d.Clock.(*sm.FakeClock).Advance(time.Hour)
	assertJSON(t, callOK(t, d, region, "RestoreSecret", map[string]any{"SecretId": created["ARN"]}), map[string]any{"ARN": created["ARN"], "Name": "secret"})
	if !reflect.DeepEqual(before, stored(t, d, "secret")) {
		t.Fatal("restore changed values or unrelated metadata")
	}
	assertJSON(t, callOK(t, d, region, "RestoreSecret", `{"SecretId":"secret"}`), map[string]any{"ARN": created["ARN"], "Name": "secret"})
	if !reflect.DeepEqual(before, stored(t, d, "secret")) {
		t.Fatal("no-op restore changed secret")
	}
	if out := callOK(t, d, region, "GetSecretValue", `{"SecretId":"secret"}`); out["SecretString"] != "initial" {
		t.Fatalf("restored value: %+v", out)
	}
}

func TestRestoreSecretExpired(t *testing.T) {
	for _, age := range []time.Duration{7 * 24 * time.Hour, 8 * 24 * time.Hour} {
		d := testDeps()
		create(t, d, "secret")
		callOK(t, d, region, "DeleteSecret", `{"SecretId":"secret","RecoveryWindowInDays":7}`)
		d.Clock.(*sm.FakeClock).Advance(age)
		before := stored(t, d, "secret")
		callError(t, d, "RestoreSecret", `{"SecretId":"secret"}`, "InvalidRequestException", "You can't restore this secret because the recovery window has expired.")
		if !reflect.DeepEqual(before, stored(t, d, "secret")) {
			t.Fatal("expired restore changed secret")
		}
	}
}

type deleteDeadlineStore struct {
	store.Store
	clock *sm.FakeClock
}

func (s deleteDeadlineStore) UpdateSecret(ctx context.Context, region, arn string, fn func(*model.Secret) error) (*model.Secret, error) {
	return s.Store.UpdateSecret(ctx, region, arn, func(current *model.Secret) error {
		// The recovery window ends after Resolve, before the atomic update.
		s.clock.Advance(time.Millisecond)
		return fn(current)
	})
}

func TestRestoreSecretChecksDeadlineDuringUpdate(t *testing.T) {
	d := testDeps()
	create(t, d, "secret")
	callOK(t, d, region, "DeleteSecret", `{"SecretId":"secret","RecoveryWindowInDays":7}`)
	clock := d.Clock.(*sm.FakeClock)
	clock.Advance(7*24*time.Hour - time.Millisecond)
	d.Store = deleteDeadlineStore{Store: d.Store, clock: clock}
	callError(t, d, "RestoreSecret", `{"SecretId":"secret"}`, "InvalidRequestException", "You can't restore this secret because the recovery window has expired.")
	if !stored(t, d, "secret").Deleted() {
		t.Fatal("restore crossed the recovery deadline")
	}
}

func TestRestoreSecretValidation(t *testing.T) {
	for _, tc := range []struct{ input, code, message string }{
		{`{}`, "ValidationException", "1 validation error detected: Value null at 'secretId' failed to satisfy constraint: Member must not be null"},
		{`{"SecretId":""}`, "ValidationException", ""},
		{`{"SecretId":"missing"}`, "ResourceNotFoundException", sm.MsgNotFound},
		{`{"SecretId":true}`, "SerializationException", ""},
	} {
		callError(t, testDeps(), "RestoreSecret", tc.input, tc.code, tc.message)
	}
	callError(t, testDeps(), "RestoreSecret", map[string]any{"SecretId": strings.Repeat("x", 2049)}, "ValidationException", "")
}

func TestDeleteRestoreSecretOwnerAccess(t *testing.T) {
	for _, op := range []string{"DeleteSecret", "RestoreSecret"} {
		for _, uid := range []*uint32{nil, new(uint32(1000)), new(uint32(1001)), new(uint32(0))} {
			d := testDeps()
			// Create under machine mode, then attach an owner to isolate authorization.
			d.Config.Server.AccessMode = "machine"
			created := create(t, d, "secret")
			_, err := d.Store.UpdateSecret(context.Background(), region, created["ARN"].(string), func(s *model.Secret) error {
				s.OwnerUID = new(uint32(1000))
				now := d.Now()
				deadline := now.Add(24 * time.Hour)
				s.DeletedDate = &now
				s.DeletionDate = &deadline
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			d.Config.Server.AccessMode = "owner"
			before := stored(t, d, "secret")
			r := httptest.NewRequest("POST", "/", bytes.NewBufferString(`{"SecretId":"secret","ForceDeleteWithoutRecovery":true}`))
			r.Header.Set("X-Amz-Target", api.TargetPrefix+op)
			w := httptest.NewRecorder()
			api.NewServer(d, uidAuth{uid}).ServeHTTP(w, r)
			if uid == nil || *uid == 1001 {
				if w.Code != 400 || api.ErrorType(w.Body.Bytes()) != "AccessDeniedException" || !strings.Contains(w.Body.String(), "secretsmanager:"+op) {
					t.Fatalf("unauthorized %s: %d %s", op, w.Code, w.Body.String())
				}
				if !reflect.DeepEqual(before, stored(t, d, "secret")) {
					t.Fatal("denied operation changed secret")
				}
			} else if w.Code != 200 {
				t.Fatalf("authorized %s: %d %s", op, w.Code, w.Body.String())
			}
		}
	}
}
