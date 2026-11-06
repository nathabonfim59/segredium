package ops_test

import (
	"bytes"
	"net/http/httptest"
	"testing"

	"github.com/nathabonfim59/segredium/internal/api"
)

func TestOwnerAccess(t *testing.T) {
	owner, other, root := uint32(1000), uint32(1001), uint32(0)
	for _, mode := range []string{"machine", "owner"} {
		t.Run(mode, func(t *testing.T) {
			d := testDeps()
			d.Config.Server.AccessMode = mode
			call := func(uid *uint32, op, body string) *httptest.ResponseRecorder {
				r := httptest.NewRequest("POST", "/", bytes.NewBufferString(body))
				r.Header.Set("X-Amz-Target", api.TargetPrefix+op)
				w := httptest.NewRecorder()
				api.NewServer(d, uidAuth{uid}).ServeHTTP(w, r)
				return w
			}
			input := `{"Name":"owned","SecretString":"initial","ClientRequestToken":"11111111-1111-4111-8111-111111111111"}`
			if w := call(&owner, "CreateSecret", input); w.Code != 200 {
				t.Fatalf("create: %d %s", w.Code, w.Body.String())
			}
			if s := stored(t, d, "owned"); s.OwnerUID == nil || *s.OwnerUID != owner {
				t.Errorf("owner not recorded: %v", s.OwnerUID)
			}
			for _, op := range []string{"GetSecretValue", "PutSecretValue", "CreateSecret"} {
				body := `{"SecretId":"owned","SecretString":"new"}`
				if op == "CreateSecret" {
					body = input
				}
				for _, uid := range []*uint32{&other, nil, &owner, &root} {
					w := call(uid, op, body)
					denied := mode == "owner" && (uid == nil || *uid == other)
					if denied {
						if w.Code != 400 || api.ErrorType(w.Body.Bytes()) != "AccessDeniedException" {
							t.Errorf("%s unauthorized: %d %s", op, w.Code, w.Body.String())
						}
					} else if w.Code != 200 {
						t.Errorf("%s authorized: %d %s", op, w.Code, w.Body.String())
					}
				}
			}
		})
	}
}
