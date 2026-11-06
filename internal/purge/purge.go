// Package purge removes secrets whose recovery windows have expired.
package purge

import (
	"context"
	"errors"
	"time"

	"github.com/nathabonfim59/segredium/internal/sm"
	"github.com/nathabonfim59/segredium/internal/store"
)

// Run sweeps immediately, then waits until the earliest known deadline or the
// configured interval. The app runs this in its worker goroutine; no others are
// started here. Metadata is held for only one region at a time.
func Run(ctx context.Context, d *sm.Deps) error { return run(ctx, d, sleep) }

func run(ctx context.Context, d *sm.Deps, wait func(context.Context, time.Duration) bool) error {
	for ctx.Err() == nil {
		delay := sweep(ctx, d)
		if !wait(ctx, delay) {
			return nil
		}
	}
	return nil
}

func sweep(ctx context.Context, d *sm.Deps) time.Duration {
	interval := d.Config.Storage.PurgeInterval
	next := d.Now().Add(interval)
	regions, err := d.Store.ListRegions(ctx)
	if err != nil {
		d.Log.Error("purge list regions", "err", err)
		return interval
	}
	for _, region := range regions {
		if ctx.Err() != nil {
			break
		}
		secrets, err := store.ListMeta(ctx, d.Store, region)
		if err != nil {
			d.Log.Error("purge list secrets", "region", region, "err", err)
			continue
		}
		for _, s := range secrets {
			if ctx.Err() != nil {
				break
			}
			if s.DeletionDate == nil {
				continue
			}
			if s.DeletionDate.After(d.Now()) {
				if s.DeletionDate.Before(next) {
					next = *s.DeletionDate
				}
				continue
			}
			// A restore may have cleared the deadline since the metadata snapshot.
			// RestoreSecret cannot restore an expired deadline, so after this read a
			// successful restoration cannot race the permanent deletion.
			current, err := d.Store.GetSecretByARN(ctx, region, s.ARN)
			if errors.Is(err, store.ErrNotFound) {
				continue
			}
			if err != nil {
				d.Log.Error("purge read secret", "arn", s.ARN, "err", err)
				continue
			}
			if current.DeletionDate == nil {
				continue
			}
			if current.DeletionDate.After(d.Now()) {
				if current.DeletionDate.Before(next) {
					next = *current.DeletionDate
				}
				continue
			}
			if err := d.Store.DeleteSecret(ctx, region, s.ARN); err != nil && !errors.Is(err, store.ErrNotFound) {
				d.Log.Error("purge delete secret", "arn", s.ARN, "err", err)
			}
		}
	}
	delay := next.Sub(d.Now())
	if delay < 0 {
		return 0
	}
	return delay
}

func sleep(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
