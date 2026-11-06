package sm

import (
	"github.com/nathabonfim59/segredium/internal/apierr"
	"github.com/nathabonfim59/segredium/internal/model"
)

// CanAccess reports whether the caller with local Unix user uid (nil = unknown) may access s.
// access_mode=machine: always. access_mode=owner: root, or the secret's owner; secrets without
// an owner are root-only, and unknown callers are denied.
func (d *Deps) CanAccess(uid *uint32, s *model.Secret) bool {
	if d.Config.Server.AccessMode != "owner" {
		return true
	}
	if uid == nil {
		return false
	}
	if *uid == 0 {
		return true
	}
	return s.OwnerUID != nil && *s.OwnerUID == *uid
}

// AccessDenied is the error for a caller CanAccess rejected (AWS's IAM-denial shape).
func AccessDenied(op string) error {
	return apierr.AccessDenied("User is not authorized to perform: secretsmanager:%s on this resource because no identity-based policy allows the action", op)
}
