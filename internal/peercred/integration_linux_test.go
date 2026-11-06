package peercred_test

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/nathabonfim59/segredium/internal/api"
	_ "github.com/nathabonfim59/segredium/internal/ops"
	"github.com/nathabonfim59/segredium/internal/peercred"
	"github.com/nathabonfim59/segredium/internal/sm"
	"github.com/nathabonfim59/segredium/internal/store/memstore"
)

func TestHTTPPeerOwnership(t *testing.T) {
	d := sm.NewTestDeps(memstore.New(), sm.NewFakeClock(time.Date(2026, 11, 6, 0, 0, 0, 0, time.UTC)))
	d.Config.Server.AccessMode = "owner"
	server := httptest.NewUnstartedServer(api.NewServer(d, nil))
	server.Config.ConnContext = peercred.ConnContext
	server.StartTLS()
	defer server.Close()
	r, err := http.NewRequest("POST", server.URL, bytes.NewBufferString(`{"Name":"owned","SecretString":"secret"}`))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("X-Amz-Target", api.TargetPrefix+"CreateSecret")
	response, err := server.Client().Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		t.Fatalf("create status: %s", response.Status)
	}
	secret, err := d.Store.GetSecretByName(context.Background(), "us-east-1", "owned")
	if err != nil {
		t.Fatal(err)
	}
	if secret.OwnerUID == nil || *secret.OwnerUID != uint32(os.Getuid()) {
		t.Fatalf("owner UID = %v, want %d", secret.OwnerUID, os.Getuid())
	}
}
