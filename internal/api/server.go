package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"time"

	"github.com/nathabonfim59/segredium/internal/apierr"
	"github.com/nathabonfim59/segredium/internal/awsjson"
	"github.com/nathabonfim59/segredium/internal/peercred"
	"github.com/nathabonfim59/segredium/internal/sm"
)

// HealthPath answers GET with 200 "ok" (not part of the AWS API).
const HealthPath = "/_segredium/health"

// maxBody bounds a request body. SecretString/SecretBinary max 65536 bytes (base64 ≈ 87 KiB);
// the largest AWS request (a 20 KiB resource policy, or a max-size secret plus metadata) stays
// well below 256 KiB, so a bigger body is never legitimate and is not buffered.
const maxBody = 256 << 10

// Server is the http.Handler for the API.
type Server struct {
	Deps *sm.Deps
	Auth Authenticator
}

// NewServer returns a Server; auth nil means ParseOnlyAuthenticator.
func NewServer(d *sm.Deps, auth Authenticator) *Server {
	if auth == nil {
		auth = ParseOnlyAuthenticator{}
	}
	return &Server{Deps: d, Auth: auth}
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	reqID, _ := sm.NewUUID(s.Deps.Rand)
	w.Header().Set("x-amzn-RequestId", reqID)
	w.Header().Set("Date", s.Deps.Now().Format(http.TimeFormat))

	if r.URL.Path == HealthPath && (r.Method == http.MethodGet || r.Method == http.MethodHead) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "ok\n")
		return
	}
	start := time.Now()
	op, status, err := s.serve(w, r, reqID)
	if err != nil {
		status = writeError(w, err)
	}
	lvl := slog.LevelInfo
	if status >= 500 {
		lvl = slog.LevelError
	}
	attrs := []any{"op", op, "status", status, "request_id", reqID, "dur", time.Since(start).Round(time.Microsecond)}
	if err != nil {
		attrs = append(attrs, "err", err.Error())
	}
	s.Deps.Log.Log(r.Context(), lvl, "request", attrs...)
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request, reqID string) (string, int, error) {
	if r.Method != http.MethodPost {
		return "", 0, apierr.UnknownOperation("Unsupported method %s", r.Method)
	}
	target := r.Header.Get("X-Amz-Target")
	op, ok := strings.CutPrefix(target, TargetPrefix)
	if !ok || op == "" {
		return "", 0, apierr.UnknownOperation("")
	}
	h, ok := lookup(op)
	if !ok {
		return op, 0, apierr.UnknownOperation("")
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
	if err != nil {
		return op, 0, apierr.Serialization("request body too large or unreadable")
	}
	id, err := s.Auth.Authenticate(r, body)
	if err != nil {
		return op, 0, err
	}
	if uid := peercred.UID(r.Context()); uid != nil {
		id.UID = uid
	}
	region := id.ScopeRegion
	if region == "" {
		region = RegionFromHost(r.Host)
	}
	if region == "" {
		region = s.Deps.Config.Server.DefaultRegion
	}
	req := &Request{Op: op, Region: region, RequestID: reqID, Identity: id, Body: body, HTTP: r}
	out, err := call(r.Context(), h, s.Deps, req)
	if err != nil {
		return op, 0, err
	}
	b := []byte("{}")
	if out != nil {
		if b, err = json.Marshal(out); err != nil {
			return op, 0, apierr.Internal("failed to encode response")
		}
	}
	w.Header().Set("Content-Type", awsjson.ContentType)
	w.Header().Set("Content-Length", strconv.Itoa(len(b)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(b)
	return op, http.StatusOK, nil
}

// call runs h, turning a panic into InternalServiceError.
func call(ctx context.Context, h Handler, d *sm.Deps, req *Request) (out any, err error) {
	defer func() {
		if p := recover(); p != nil {
			d.Log.Error("handler panic", "op", req.Op, "panic", p)
			out, err = nil, apierr.Internal("An error occurred on the server side.")
		}
	}()
	return h(ctx, d, req)
}

type errorBody struct {
	Type    string `json:"__type"`
	Message string `json:"Message,omitempty"`
}

// writeError encodes err the AWS JSON 1.1 way and returns the HTTP status.
func writeError(w http.ResponseWriter, err error) int {
	e := apierr.As(err)
	if e == nil {
		e = apierr.Internal("An error occurred on the server side.")
	}
	b, _ := json.Marshal(errorBody{Type: e.Code, Message: e.Message})
	w.Header().Set("Content-Type", awsjson.ContentType)
	w.Header().Set("x-amzn-ErrorType", e.Code)
	w.Header().Set("Content-Length", strconv.Itoa(len(b)))
	w.WriteHeader(e.Status)
	_, _ = w.Write(b)
	return e.Status
}

// TestCall invokes op through the full HTTP handler (auth = parse-only) and returns the status
// and response body. region "" uses the default region. Intended for ops tests.
func TestCall(d *sm.Deps, region, op string, in any) (int, []byte) {
	var body []byte
	switch v := in.(type) {
	case nil:
	case string:
		body = []byte(v)
	case []byte:
		body = v
	default:
		var err error
		if body, err = json.Marshal(v); err != nil {
			panic(err)
		}
	}
	r := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	r.Header.Set("Content-Type", awsjson.ContentType)
	r.Header.Set("X-Amz-Target", TargetPrefix+op)
	if region != "" {
		r.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=AKIDTEST/20261106/"+region+"/secretsmanager/aws4_request, SignedHeaders=host, Signature=00")
	}
	rec := httptest.NewRecorder()
	NewServer(d, nil).ServeHTTP(rec, r)
	return rec.Code, rec.Body.Bytes()
}

// ErrorType extracts "__type" from an error response body ("" if absent).
func ErrorType(body []byte) string {
	var e errorBody
	_ = json.Unmarshal(body, &e)
	return e.Type
}
