package ops_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/nathabonfim59/segredium/internal/api"
	"github.com/nathabonfim59/segredium/internal/model"
	"github.com/nathabonfim59/segredium/internal/sm"
)

func seedMetadata(t *testing.T, d *sm.Deps, name string, change func(*model.Secret)) *model.Secret {
	t.Helper()
	s := &model.Secret{ARN: sm.ARN(region, d.AccountID(), name, "abcdef"), Name: name, Region: region, CreatedDate: d.Now()}
	if change != nil {
		change(s)
	}
	if err := d.Store.CreateSecret(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestDescribeSecretWire(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*model.Secret)
		want   func(*model.Secret) map[string]any
	}{
		{"minimal", nil, func(s *model.Secret) map[string]any { return minimalMetadata(s) }},
		{"default key omitted", func(s *model.Secret) { s.KmsKeyID = model.DefaultKMSKeyID }, func(s *model.Secret) map[string]any { return minimalMetadata(s) }},
		{"full metadata", func(s *model.Secret) {
			now := dTime()
			later := now.Add(30 * 24 * time.Hour)
			uid := uint32(1000)
			days := int64(30)
			duration, schedule := "2h", "rate(30 days)"
			s.Description, s.KmsKeyID, s.Type = "description", "alias/custom", "partner"
			s.RotationEnabled, s.RotationLambdaARN = true, "arn:aws:lambda:us-east-1:123456789012:function:rotate"
			s.RotationRules = &model.RotationRules{AutomaticallyAfterDays: &days, Duration: &duration, ScheduleExpression: &schedule}
			s.LastChangedDate, s.LastRotatedDate, s.NextRotationDate = &now, &now, &later
			s.LastAccessedDate, s.DeletedDate, s.DeletionDate = &now, &now, &later
			s.Tags = []model.Tag{{Key: "Environment", Value: "Production"}}
			s.ExternalSecretRotationMetadata = []model.Tag{{Key: "key", Value: "metadata"}}
			s.ExternalSecretRotationRoleArn = "arn:aws:iam::123456789012:role/rotation"
			s.OwningService, s.PrimaryRegion, s.OwnerUID = "rds", region, &uid
			s.ResourcePolicy = "must never appear"
			s.Replicas = []model.ReplicationStatus{{Region: "us-west-2", KmsKeyID: "alias/replica", Status: "InSync", StatusMessage: "replicated", LastAccessedDate: &now}}
			value := "must never appear"
			s.Versions = []*model.Version{
				{VersionID: token1, SecretString: &value, Stages: []string{"AWSCURRENT", "custom"}, CreatedDate: now},
				{VersionID: token2, SecretBinary: []byte("must never appear"), CreatedDate: now},
			}
		}, func(s *model.Secret) map[string]any {
			out := minimalMetadata(s)
			out["Description"], out["KmsKeyId"], out["Type"] = s.Description, s.KmsKeyID, s.Type
			out["RotationEnabled"], out["RotationLambdaARN"], out["RotationRules"] = true, s.RotationLambdaARN, s.RotationRules
			out["LastChangedDate"], out["LastRotatedDate"], out["NextRotationDate"] = epoch(*s.LastChangedDate), epoch(*s.LastRotatedDate), epoch(*s.NextRotationDate)
			out["LastAccessedDate"], out["DeletedDate"] = model.Day(*s.LastAccessedDate).Unix(), epoch(*s.DeletedDate)
			out["Tags"], out["ExternalSecretRotationMetadata"] = s.Tags, s.ExternalSecretRotationMetadata
			out["ExternalSecretRotationRoleArn"] = s.ExternalSecretRotationRoleArn
			out["OwningService"], out["PrimaryRegion"] = s.OwningService, s.PrimaryRegion
			out["VersionIdsToStages"] = map[string][]string{token1: {"AWSCURRENT", "custom"}}
			out["ReplicationStatus"] = []map[string]any{{"Region": "us-west-2", "KmsKeyId": "alias/replica", "Status": "InSync", "StatusMessage": "replicated", "LastAccessedDate": model.Day(*s.LastAccessedDate).Unix()}}
			return out
		}},
		{"rotation cancelled", func(s *model.Secret) { s.RotationRules = &model.RotationRules{} }, func(s *model.Secret) map[string]any {
			out := minimalMetadata(s)
			out["RotationEnabled"], out["RotationRules"] = false, map[string]any{}
			return out
		}},
		{"replica default key", func(s *model.Secret) {
			s.Replicas = []model.ReplicationStatus{{Region: "us-west-2", KmsKeyID: model.DefaultKMSKeyID, Status: "InProgress"}}
		}, func(s *model.Secret) map[string]any {
			out := minimalMetadata(s)
			out["ReplicationStatus"] = []map[string]any{{"Region": "us-west-2", "Status": "InProgress"}}
			return out
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := testDeps()
			s := seedMetadata(t, d, "secret", tc.change)
			for _, id := range []string{s.Name, s.ARN, strings.TrimSuffix(s.ARN, "-abcdef")} {
				out := callOK(t, d, region, "DescribeSecret", map[string]any{"SecretId": id})
				assertJSON(t, out, tc.want(s))
			}
			if !reflect.DeepEqual(s, stored(t, d, s.Name)) {
				t.Fatal("DescribeSecret changed stored state")
			}
		})
	}
}

func dTime() time.Time { return time.Date(2026, 11, 6, 13, 14, 15, 123000000, time.UTC) }

func epoch(t time.Time) float64 { return float64(t.UnixMilli()) / 1000 }

func minimalMetadata(s *model.Secret) map[string]any {
	return map[string]any{"ARN": s.ARN, "Name": s.Name, "CreatedDate": epoch(s.CreatedDate)}
}

func TestDescribeSecretErrors(t *testing.T) {
	for _, tc := range []struct{ name, input, code, message string }{
		{"missing id", `{}`, "ValidationException", "1 validation error detected: Value null at 'secretId' failed to satisfy constraint: Member must not be null"},
		{"null id", `{"SecretId":null}`, "ValidationException", ""},
		{"empty id", `{"SecretId":""}`, "ValidationException", ""},
		{"wrong type", `{"SecretId":1}`, "SerializationException", "Start of structure or map found where not expected"},
		{"not found", `{"SecretId":"missing"}`, "ResourceNotFoundException", sm.MsgNotFound},
	} {
		t.Run(tc.name, func(t *testing.T) { callError(t, testDeps(), "DescribeSecret", tc.input, tc.code, tc.message) })
	}
	d := testDeps()
	seedMetadata(t, d, "secret", nil)
	callError(t, d, "DescribeSecret", map[string]any{"SecretId": strings.Repeat("x", 2049)}, "ValidationException", "")
	status, body := api.TestCall(d, "us-west-2", "DescribeSecret", `{"SecretId":"secret"}`)
	if status != 400 || api.ErrorType(body) != "ResourceNotFoundException" {
		t.Fatalf("region isolation: %d %s", status, body)
	}
}

type uidAuth struct{ uid *uint32 }

func (a uidAuth) Authenticate(*http.Request, []byte) (api.Identity, error) {
	return api.Identity{UID: a.uid}, nil
}

// TestCall deliberately uses parse-only auth; owner-mode cases need an injected identity.
func callAsUID(t *testing.T, d *sm.Deps, uid *uint32, op string, in any) (int, []byte) {
	t.Helper()
	body, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "https://secretsmanager."+region+".amazonaws.com/", bytes.NewReader(body))
	r.Header.Set("X-Amz-Target", api.TargetPrefix+op)
	w := httptest.NewRecorder()
	api.NewServer(d, uidAuth{uid}).ServeHTTP(w, r)
	return w.Code, w.Body.Bytes()
}

func TestDescribeSecretAccess(t *testing.T) {
	owner, other, root := uint32(1000), uint32(1001), uint32(0)
	for _, tc := range []struct {
		name string
		mode string
		uid  *uint32
		code int
	}{
		{"machine unknown", "machine", nil, 200},
		{"owner", "owner", &owner, 200},
		{"root", "owner", &root, 200},
		{"other user", "owner", &other, 400},
		{"unknown user", "owner", nil, 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := testDeps()
			d.Config.Server.AccessMode = tc.mode
			seedMetadata(t, d, "secret", func(s *model.Secret) { s.OwnerUID = &owner })
			status, body := callAsUID(t, d, tc.uid, "DescribeSecret", map[string]any{"SecretId": "secret"})
			if status != tc.code {
				t.Fatalf("status %d: %s", status, body)
			}
			if status != 200 && api.ErrorType(body) != "AccessDeniedException" {
				t.Fatalf("wrong error: %s", body)
			}
			if status != 200 && !bytes.Contains(body, []byte("secretsmanager:DescribeSecret")) {
				t.Fatalf("missing operation in denial: %s", body)
			}
		})
	}
}
