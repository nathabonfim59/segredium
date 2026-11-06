// Package api is the HTTP front end: the AWS JSON 1.1 protocol for the secretsmanager service.
//
// Requests: POST / with header X-Amz-Target: secretsmanager.<Operation> and a JSON body.
// Responses: 200 with a JSON body, or an error status with {"__type": <code>, "Message": <msg>}.
package api

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/nathabonfim59/segredium/internal/awsjson"
	"github.com/nathabonfim59/segredium/internal/sm"
)

// TargetPrefix is the X-Amz-Target prefix of the service.
const TargetPrefix = "secretsmanager."

// Request is one decoded API call.
type Request struct {
	Op        string
	Region    string
	RequestID string
	Identity  Identity
	Body      []byte
	HTTP      *http.Request
}

// Decode unmarshals the body into v (SerializationException on malformed input).
func (r *Request) Decode(v any) error { return awsjson.DecodeBytes(r.Body, v) }

// Handler implements one operation. It returns the output struct (marshalled as JSON; nil → {})
// or an error (*apierr.Error for API errors; anything else → InternalServiceError).
type Handler func(ctx context.Context, d *sm.Deps, r *Request) (any, error)

var (
	regMu    sync.RWMutex
	registry = map[string]Handler{}
)

// Register adds an operation. Call it from an init() in internal/ops. Panics on duplicates.
func Register(op string, h Handler) {
	regMu.Lock()
	defer regMu.Unlock()
	if _, dup := registry[op]; dup {
		panic("api: duplicate operation " + op)
	}
	registry[op] = h
}

func lookup(op string) (Handler, bool) {
	regMu.RLock()
	defer regMu.RUnlock()
	h, ok := registry[op]
	return h, ok
}

// Operations lists registered operation names, sorted.
func Operations() []string {
	regMu.RLock()
	defer regMu.RUnlock()
	out := make([]string, 0, len(registry))
	for k := range registry {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Identity is who made the request, as far as the authenticator could tell.
type Identity struct {
	AccessKeyID string
	// Region from the SigV4 credential scope ("" if unsigned).
	ScopeRegion string
	// UID is the local Unix user of the connection's peer, when segredium could determine
	// it (loopback TCP); nil otherwise. Used by server.access_mode=owner.
	UID *uint32
}

// Authenticator validates a request before dispatch. body is the full request body (already
// read). It returns an *apierr.Error to reject the request.
type Authenticator interface {
	Authenticate(r *http.Request, body []byte) (Identity, error)
}

// TLSProvider supplies the HTTPS listener's configuration (e.g. the built-in CA via SNI).
type TLSProvider interface {
	TLSConfig() (*tls.Config, error)
}

// ParseOnlyAuthenticator accepts every request and only extracts the access key and region
// from an Authorization header or presigned query, if present. It is auth.mode=none.
type ParseOnlyAuthenticator struct{}

var credRe = regexp.MustCompile(`Credential=([^/,\s]+)/(\d{8})/([^/]+)/([^/]+)/aws4_request`)

func (ParseOnlyAuthenticator) Authenticate(r *http.Request, _ []byte) (Identity, error) {
	return ParseCredentialScope(r), nil
}

// ParseCredentialScope extracts the access key id and region from a SigV4 Authorization header
// or X-Amz-Credential query parameter, without verifying anything.
func ParseCredentialScope(r *http.Request) Identity {
	if m := credRe.FindStringSubmatch(r.Header.Get("Authorization")); m != nil {
		return Identity{AccessKeyID: m[1], ScopeRegion: m[3]}
	}
	if c := r.URL.Query().Get("X-Amz-Credential"); c != "" {
		p := strings.Split(c, "/")
		if len(p) == 5 {
			return Identity{AccessKeyID: p[0], ScopeRegion: p[2]}
		}
	}
	return Identity{}
}

var hostRe = regexp.MustCompile(`^secretsmanager(?:-fips)?\.([a-z0-9-]+)\.(?:amazonaws\.com(?:\.cn)?|api\.aws|api\.amazonwebservices\.com\.cn|c2s\.ic\.gov|sc2s\.sgov\.gov)$`)

// RegionFromHost returns the region named by a secretsmanager endpoint hostname, or "".
func RegionFromHost(host string) string {
	if h, _, ok := strings.Cut(host, ":"); ok {
		host = h
	}
	m := hostRe.FindStringSubmatch(strings.ToLower(host))
	if m == nil {
		return ""
	}
	return m[1]
}

// FilesTLSProvider serves a fixed certificate/key pair (tls.mode=files).
type FilesTLSProvider struct{ CertFile, KeyFile string }

func (f FilesTLSProvider) TLSConfig() (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(f.CertFile, f.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("tls: %w", err)
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}, nil
}
