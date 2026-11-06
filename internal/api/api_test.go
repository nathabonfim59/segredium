package api_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nathabonfim59/segredium/internal/api"
	"github.com/nathabonfim59/segredium/internal/apierr"
	"github.com/nathabonfim59/segredium/internal/sm"
	"github.com/nathabonfim59/segredium/internal/store/memstore"
)

type echoIn struct {
	SecretId *string
	N        *int64
}

func init() {
	api.Register("ZzEcho", func(ctx context.Context, d *sm.Deps, r *api.Request) (any, error) {
		var in echoIn
		if err := r.Decode(&in); err != nil {
			return nil, err
		}
		if in.SecretId != nil && *in.SecretId == "missing" {
			return nil, apierr.ResourceNotFound(sm.MsgNotFound)
		}
		if in.SecretId != nil && *in.SecretId == "panic" {
			panic("boom")
		}
		return map[string]any{"Region": r.Region, "Key": r.Identity.AccessKeyID}, nil
	})
}

func deps() *sm.Deps {
	return sm.NewTestDeps(memstore.New(), sm.NewFakeClock(time.Date(2026, 11, 6, 0, 0, 0, 0, time.UTC)))
}

func TestDispatchAndRegion(t *testing.T) {
	code, body := api.TestCall(deps(), "eu-west-1", "ZzEcho", map[string]any{"SecretId": "x"})
	if code != 200 || string(body) != `{"Key":"AKIDTEST","Region":"eu-west-1"}` {
		t.Fatalf("%d %s", code, body)
	}
	code, body = api.TestCall(deps(), "", "ZzEcho", "")
	if code != 200 || !strings.Contains(string(body), `"Region":"us-east-1"`) {
		t.Fatalf("default region: %d %s", code, body)
	}
}

func TestHostRegion(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{}"))
	r.Host = "secretsmanager.ap-southeast-2.amazonaws.com"
	r.Header.Set("X-Amz-Target", "secretsmanager.ZzEcho")
	w := httptest.NewRecorder()
	api.NewServer(deps(), nil).ServeHTTP(w, r)
	if !strings.Contains(w.Body.String(), "ap-southeast-2") {
		t.Fatal(w.Body.String())
	}
	for host, want := range map[string]string{
		"secretsmanager.us-east-1.amazonaws.com:443":      "us-east-1",
		"secretsmanager-fips.us-gov-west-1.amazonaws.com": "us-gov-west-1",
		"secretsmanager.eu-central-1.api.aws":             "eu-central-1",
		"secretsmanager.cn-north-1.amazonaws.com.cn":      "cn-north-1",
		"localhost:8080": "",
	} {
		if got := api.RegionFromHost(host); got != want {
			t.Errorf("%s: got %q want %q", host, got, want)
		}
	}
}

func TestErrors(t *testing.T) {
	cases := []struct {
		op, body, wantType string
		wantCode           int
	}{
		{"ZzEcho", `{"SecretId":"missing"}`, "ResourceNotFoundException", 400},
		{"ZzEcho", `{"SecretId":5}`, "SerializationException", 400},
		{"ZzEcho", `{bad json`, "SerializationException", 400},
		{"ZzEcho", `{"SecretId":"panic"}`, "InternalServiceError", 500},
		{"NoSuchOp", `{}`, "UnknownOperationException", 400},
	}
	for _, c := range cases {
		code, body := api.TestCall(deps(), "us-east-1", c.op, c.body)
		if code != c.wantCode || api.ErrorType(body) != c.wantType {
			t.Errorf("%s %s: got %d %s", c.op, c.body, code, body)
		}
	}
	code, body := api.TestCall(deps(), "us-east-1", "ZzEcho", `{"SecretId":"missing"}`)
	if code != 400 || string(body) != `{"__type":"ResourceNotFoundException","Message":"Secrets Manager can't find the specified secret."}` {
		t.Fatalf("exact error body: %s", body)
	}
}

func TestHealthAndMethod(t *testing.T) {
	s := api.NewServer(deps(), nil)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest(http.MethodGet, api.HealthPath, nil))
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	w = httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	if w.Code != 400 || w.Header().Get("x-amzn-RequestId") == "" || w.Header().Get("x-amzn-ErrorType") != "UnknownOperationException" {
		t.Fatalf("%d %v", w.Code, w.Header())
	}
}

func TestPresignedScope(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/?X-Amz-Credential=AKID%2F20261106%2Fsa-east-1%2Fsecretsmanager%2Faws4_request", nil)
	id := api.ParseCredentialScope(r)
	if id.AccessKeyID != "AKID" || id.ScopeRegion != "sa-east-1" {
		t.Fatalf("%+v", id)
	}
}
