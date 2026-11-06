package sm

import (
	"fmt"
	"regexp"
	"unicode/utf8"

	"github.com/nathabonfim59/segredium/internal/apierr"
)

// Validator collects service-model constraint violations (required, length, range, pattern)
// and reports them as one ValidationException in AWS's format. Member names are written as
// AWS writes them in these messages: lowerCamelCase of the member (e.g. "secretId").
//
//	v := sm.Validator{}
//	v.Required("secretId", in.SecretId != nil)
//	v.Length("secretId", in.SecretId, 1, 2048)
//	if err := v.Err(); err != nil { return nil, err }
type Validator struct{ violations []string }

func (v *Validator) add(format string, a ...any) {
	v.violations = append(v.violations, fmt.Sprintf(format, a...))
}

// Required records "Value null at 'm' failed to satisfy constraint: Member must not be null".
func (v *Validator) Required(member string, present bool) {
	if !present {
		v.add("Value null at '%s' failed to satisfy constraint: Member must not be null", member)
	}
}

// Length checks a string's length in characters (nil = skip).
func (v *Validator) Length(member string, s *string, min, max int) {
	if s == nil {
		return
	}
	n := utf8.RuneCountInString(*s)
	if n < min {
		v.add("Value '%s' at '%s' failed to satisfy constraint: Member must have length greater than or equal to %d", *s, member, min)
	}
	if max >= 0 && n > max {
		v.add("Value '%s' at '%s' failed to satisfy constraint: Member must have length less than or equal to %d", *s, member, max)
	}
}

// SensitiveLength is Length for sensitive members (SecretString, passwords): AWS never echoes
// their value, and neither may we (messages are returned to clients and logged).
func (v *Validator) SensitiveLength(member string, s *string, min, max int) {
	if s == nil {
		return
	}
	n := utf8.RuneCountInString(*s)
	if n < min {
		v.add("Value at '%s' failed to satisfy constraint: Member must have length greater than or equal to %d", member, min)
	}
	if max >= 0 && n > max {
		v.add("Value at '%s' failed to satisfy constraint: Member must have length less than or equal to %d", member, max)
	}
}

// BytesLength checks a blob's length in bytes (nil = skip). The value is not echoed.
func (v *Validator) BytesLength(member string, b []byte, min, max int) {
	if b == nil {
		return
	}
	if len(b) < min {
		v.add("Value at '%s' failed to satisfy constraint: Member must have length greater than or equal to %d", member, min)
	}
	if max >= 0 && len(b) > max {
		v.add("Value at '%s' failed to satisfy constraint: Member must have length less than or equal to %d", member, max)
	}
}

// Range checks an integer (nil = skip).
func (v *Validator) Range(member string, n *int64, min, max int64) {
	if n == nil {
		return
	}
	if *n < min {
		v.add("Value '%d' at '%s' failed to satisfy constraint: Member must have value greater than or equal to %d", *n, member, min)
	}
	if *n > max {
		v.add("Value '%d' at '%s' failed to satisfy constraint: Member must have value less than or equal to %d", *n, member, max)
	}
}

// Pattern checks a string against the service model's regex (nil = skip).
func (v *Validator) Pattern(member string, s *string, re *regexp.Regexp) {
	if s == nil || re.MatchString(*s) {
		return
	}
	v.add("Value '%s' at '%s' failed to satisfy constraint: Member must satisfy regular expression pattern: %s", *s, member, re.String())
}

// Custom records a free-form violation.
func (v *Validator) Custom(msg string) { v.violations = append(v.violations, msg) }

// Err returns nil or the ValidationException.
func (v *Validator) Err() error {
	if len(v.violations) == 0 {
		return nil
	}
	return apierr.ValidationErrors(v.violations)
}
