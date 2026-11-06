package ops

import (
	"context"
	"errors"

	"github.com/nathabonfim59/segredium/internal/apierr"
	"github.com/nathabonfim59/segredium/internal/model"
	"github.com/nathabonfim59/segredium/internal/sm"
	"github.com/nathabonfim59/segredium/internal/store"
)

const (
	msgDeleted       = "You can't perform this operation on the secret because it was marked for deletion."
	msgTokenConflict = "You can't use the currently specified client request token because a version with the same token but a different secret value already exists."
)

// Returning this from an atomic update skips the store's final clone and write on retries.
var errUnchanged = errors.New("secret unchanged")

func validateValue(v *sm.Validator, text *string, binary []byte) {
	v.SensitiveLength("secretString", text, 1, 65536)
	v.BytesLength("secretBinary", binary, 1, 65536)
}

func valueConflict(text *string, binary []byte, required bool) error {
	if text != nil && binary != nil {
		return apierr.InvalidParameter("You can't specify both SecretBinary and SecretString.")
	}
	if required && text == nil && binary == nil {
		return apierr.InvalidRequest("You must provide either SecretString or SecretBinary.")
	}
	return nil
}

func storeError(err error) error {
	if errors.Is(err, store.ErrNotFound) {
		return apierr.ResourceNotFound(sm.MsgNotFound)
	}
	return err
}

func syncReplicas(ctx context.Context, d *sm.Deps, s *model.Secret) {
	if len(s.Replicas) > 0 {
		if err := d.Replicator.Sync(ctx, s); err != nil {
			d.Log.Error("replicate secret", "arn", s.ARN, "err", err)
		}
	}
}
