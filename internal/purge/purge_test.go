package purge

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/nathabonfim59/segredium/internal/model"
	"github.com/nathabonfim59/segredium/internal/sm"
	"github.com/nathabonfim59/segredium/internal/store"
	"github.com/nathabonfim59/segredium/internal/store/memstore"
)

type purgeStore struct {
	store.Store
	listRegionsErr                    error
	listErr, readErr, deleteErr       map[string]error
	onRead                            func(context.Context, string, string)
	metaCalls, readCalls, deleteCalls int
}

func (s *purgeStore) ListRegions(ctx context.Context) ([]string, error) {
	if s.listRegionsErr != nil {
		return nil, s.listRegionsErr
	}
	return s.Store.ListRegions(ctx)
}
func (s *purgeStore) ListSecrets(context.Context, string) ([]*model.Secret, error) {
	panic("purge copied payloads through ListSecrets")
}
func (s *purgeStore) ListSecretsMeta(ctx context.Context, region string) ([]*model.Secret, error) {
	s.metaCalls++
	if err := s.listErr[region]; err != nil {
		return nil, err
	}
	return store.ListMeta(ctx, s.Store, region)
}
func (s *purgeStore) GetSecretByARN(ctx context.Context, region, arn string) (*model.Secret, error) {
	s.readCalls++
	if s.onRead != nil {
		s.onRead(ctx, region, arn)
	}
	if err := s.readErr[arn]; err != nil {
		return nil, err
	}
	return s.Store.GetSecretByARN(ctx, region, arn)
}
func (s *purgeStore) DeleteSecret(ctx context.Context, region, arn string) error {
	s.deleteCalls++
	if err := s.deleteErr[arn]; err != nil {
		return err
	}
	return s.Store.DeleteSecret(ctx, region, arn)
}

func purgeDeps() (*sm.Deps, *purgeStore) {
	s := &purgeStore{Store: memstore.New()}
	return sm.NewTestDeps(s, sm.NewFakeClock(time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC))), s
}

func purgeAdd(t *testing.T, d *sm.Deps, region, name string, deadline *time.Time) string {
	t.Helper()
	arn := sm.ARN(region, d.AccountID(), name, "abcdef")
	s := &model.Secret{ARN: arn, Name: name, Region: region, CreatedDate: d.Now(), DeletionDate: deadline, Versions: []*model.Version{{VersionID: "version", SecretString: new("payload")}}}
	if deadline != nil {
		now := d.Now()
		s.DeletedDate = &now
	}
	if err := d.Store.CreateSecret(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	return arn
}

func TestPurgeInitialSweepAndDeadlines(t *testing.T) {
	d, s := purgeDeps()
	now := d.Now()
	past, soon, later := now.Add(-time.Second), now.Add(10*time.Minute), now.Add(2*time.Hour)
	active := purgeAdd(t, d, "us-east-1", "active", nil)
	old := purgeAdd(t, d, "us-east-1", "old", &past)
	due := purgeAdd(t, d, "us-west-2", "due", &now)
	upcoming := purgeAdd(t, d, "us-west-2", "soon", &soon)
	late := purgeAdd(t, d, "us-east-1", "later", &later)
	waits := 0
	err := run(context.Background(), d, func(ctx context.Context, delay time.Duration) bool {
		waits++
		want := 10 * time.Minute
		if waits == 2 {
			want = time.Hour
		}
		if delay != want {
			t.Fatalf("sleep %d = %v, want %v", waits, delay, want)
		}
		for _, tc := range []struct {
			region, arn string
			gone        bool
		}{{"us-east-1", old, true}, {"us-west-2", due, true}, {"us-west-2", upcoming, waits == 2}, {"us-east-1", active, false}, {"us-east-1", late, false}} {
			_, err := s.Store.GetSecretByARN(ctx, tc.region, tc.arn)
			if tc.gone && !errors.Is(err, store.ErrNotFound) || !tc.gone && err != nil {
				t.Fatalf("%s gone=%t: %v", tc.arn, tc.gone, err)
			}
		}
		if waits == 2 {
			return false
		}
		d.Clock.(*sm.FakeClock).Advance(delay)
		return true
	})
	if err != nil || waits != 2 || s.metaCalls != 4 || s.readCalls != 3 || s.deleteCalls != 3 {
		t.Fatalf("run: err=%v waits=%d meta=%d reads=%d deletes=%d", err, waits, s.metaCalls, s.readCalls, s.deleteCalls)
	}
}

func TestPurgeRereadsSnapshot(t *testing.T) {
	for _, postpone := range []bool{false, true} {
		d, s := purgeDeps()
		now := d.Now()
		arn := purgeAdd(t, d, "us-east-1", "stale", &now)
		s.onRead = func(ctx context.Context, region, arn string) {
			_, err := s.Store.UpdateSecret(ctx, region, arn, func(current *model.Secret) error {
				current.DeletedDate, current.DeletionDate = nil, nil
				if postpone {
					later := now.Add(15 * time.Minute)
					current.DeletedDate = &now
					current.DeletionDate = &later
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
		}
		want := time.Hour
		if postpone {
			want = 15 * time.Minute
		}
		if delay := sweep(context.Background(), d); delay != want {
			t.Fatalf("delay=%v, want %v", delay, want)
		}
		if s.readCalls != 1 || s.deleteCalls != 0 {
			t.Fatalf("reads=%d deletes=%d", s.readCalls, s.deleteCalls)
		}
		if _, err := s.Store.GetSecretByARN(context.Background(), "us-east-1", arn); err != nil {
			t.Fatal(err)
		}
	}
}

func TestPurgeErrorsContinueAndRetryWithoutSpin(t *testing.T) {
	d, s := purgeDeps()
	var logs bytes.Buffer
	d.Log = slog.New(slog.NewTextHandler(&logs, nil))
	now := d.Now()
	purgeAdd(t, d, "ap-south-1", "list-fails", &now)
	readFail := purgeAdd(t, d, "us-east-1", "read-fails", &now)
	deleteFail := purgeAdd(t, d, "us-east-1", "delete-fails", &now)
	readMissing := purgeAdd(t, d, "us-east-1", "read-missing", &now)
	deleteMissing := purgeAdd(t, d, "us-east-1", "delete-missing", &now)
	good := purgeAdd(t, d, "us-west-2", "good", &now)
	failure := errors.New("injected failure")
	s.listErr = map[string]error{"ap-south-1": failure}
	s.readErr = map[string]error{readFail: failure, readMissing: store.ErrNotFound}
	s.deleteErr = map[string]error{deleteFail: failure, deleteMissing: store.ErrNotFound}
	if delay := sweep(context.Background(), d); delay != time.Hour {
		t.Fatalf("error retry delay = %v", delay)
	}
	if _, err := s.Store.GetSecretByARN(context.Background(), "us-west-2", good); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("other-region sweep stopped: %v", err)
	}
	if strings.Count(logs.String(), "injected failure") != 3 || strings.Contains(logs.String(), "secret not found") {
		t.Fatalf("logs: %s", logs.String())
	}
	s.listRegionsErr = failure
	if delay := sweep(context.Background(), d); delay != time.Hour || !strings.Contains(logs.String(), "purge list regions") {
		t.Fatalf("list regions failure: %v %s", delay, logs.String())
	}
}

func TestPurgeCancellation(t *testing.T) {
	d, s := purgeDeps()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := run(ctx, d, func(context.Context, time.Duration) bool { t.Fatal("cancelled run slept"); return false }); err != nil {
		t.Fatal(err)
	}
	if s.metaCalls != 0 {
		t.Fatal("cancelled run swept")
	}
	if sleep(ctx, time.Hour) {
		t.Fatal("cancelled sleep returned true")
	}
	ctx, cancel = context.WithCancel(context.Background())
	err := run(ctx, d, func(ctx context.Context, delay time.Duration) bool {
		if delay != time.Hour {
			t.Fatalf("empty-store sleep=%v", delay)
		}
		cancel()
		return sleep(ctx, delay)
	})
	if err != nil {
		t.Fatal(err)
	}
}
