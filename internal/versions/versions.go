// Package versions implements Secrets Manager staging labels and version retention.
package versions

import (
	"bytes"
	"slices"
	"time"

	"github.com/nathabonfim59/segredium/internal/apierr"
	"github.com/nathabonfim59/segredium/internal/model"
)

// SameValue compares payloads without treating string and binary values as interchangeable.
func SameValue(v *model.Version, text *string, binary []byte) bool {
	if (v.SecretString == nil) != (text == nil) || (v.SecretBinary == nil) != (binary == nil) {
		return false
	}
	return (text == nil || *v.SecretString == *text) && bytes.Equal(v.SecretBinary, binary)
}

// Attach moves each requested label to target. Moving AWSCURRENT also moves AWSPREVIOUS
// to its former owner. See API_PutSecretValue.html. Call within Store.UpdateSecret so a
// subsequent quota error rolls back all label moves.
func Attach(s *model.Secret, target *model.Version, stages []string) error {
	previous := s.VersionByStage(model.StageCurrent)
	for _, stage := range stages {
		move(s, target, stage)
	}
	if slices.Contains(stages, model.StageCurrent) && previous != nil && previous != target {
		move(s, previous, model.StagePrevious)
	}
	// AWS's quota applies across all versions, not separately to each version.
	// https://docs.aws.amazon.com/secretsmanager/latest/userguide/reference_limits.html
	n := 0
	for _, v := range s.Versions {
		n += len(v.Stages)
	}
	if n > 20 {
		return apierr.LimitExceeded("You exceeded the maximum number of staging labels for a single secret.")
	}
	return nil
}

func move(s *model.Secret, target *model.Version, stage string) {
	for _, v := range s.Versions {
		if v != target {
			v.Stages = slices.DeleteFunc(v.Stages, func(label string) bool { return label == stage })
		}
	}
	if !target.HasStage(stage) {
		target.Stages = append(target.Stages, stage)
	}
}

// Prune retains at most 100 versions, removing the oldest deprecated versions first.
// AWS never removes labeled versions or versions less than 24 hours old. See
// https://docs.aws.amazon.com/secretsmanager/latest/userguide/getting-started.html#term_version
// Call within Store.UpdateSecret; errors must roll back the enclosing mutation.
func Prune(s *model.Secret, now time.Time) error {
	cutoff := now.Add(-24 * time.Hour)
	for len(s.Versions) > 100 {
		oldest := -1
		for i, v := range s.Versions {
			if len(v.Stages) == 0 && !v.CreatedDate.After(cutoff) && (oldest == -1 || v.CreatedDate.Before(s.Versions[oldest].CreatedDate)) {
				oldest = i
			}
		}
		if oldest == -1 {
			return apierr.LimitExceeded("You exceeded the maximum number of versions for a secret. Remove staging labels from older versions to allow Secrets Manager to delete them.")
		}
		// Delete clears the removed pointer, so the backing array cannot retain payloads.
		s.Versions = slices.Delete(s.Versions, oldest, oldest+1)
	}
	return nil
}
