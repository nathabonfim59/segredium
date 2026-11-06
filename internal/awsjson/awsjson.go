// Package awsjson implements the AWS JSON 1.1 wire conventions used by Secrets Manager.
package awsjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"time"

	"github.com/nathabonfim59/segredium/internal/apierr"
)

// ContentType is the request/response media type of the protocol.
const ContentType = "application/x-amz-json-1.1"

// Time is a timestamp serialized as epoch seconds with millisecond precision
// (e.g. 1762430000.123), which is how AWS JSON 1.1 encodes timestamps.
type Time struct{ time.Time }

// NewTime returns a *Time, or nil for the zero time (so omitempty drops it).
func NewTime(t time.Time) *Time {
	if t.IsZero() {
		return nil
	}
	return &Time{t}
}

// TimePtr converts a *time.Time (nil-able model field) to *Time.
func TimePtr(t *time.Time) *Time {
	if t == nil || t.IsZero() {
		return nil
	}
	return &Time{*t}
}

func (t Time) MarshalJSON() ([]byte, error) {
	ms := t.UnixMilli()
	return []byte(strconv.FormatFloat(float64(ms)/1000, 'f', -1, 64)), nil
}

func (t *Time) UnmarshalJSON(b []byte) error {
	if string(b) == "null" {
		return nil
	}
	f, err := strconv.ParseFloat(string(b), 64)
	if err != nil {
		return fmt.Errorf("timestamp must be epoch seconds: %w", err)
	}
	sec := int64(f)
	t.Time = time.Unix(sec, int64((f-float64(sec))*1e9)).UTC().Truncate(time.Millisecond)
	return nil
}

// Decode reads a JSON request body into v. An empty body is treated as "{}".
// Malformed JSON or a type mismatch becomes SerializationException, like AWS.
// Unknown members are ignored (AWS ignores them too).
func Decode(r io.Reader, v any) error {
	body, err := io.ReadAll(io.LimitReader(r, 10<<20))
	if err != nil {
		return apierr.Serialization("failed to read request body")
	}
	return DecodeBytes(body, v)
}

// DecodeBytes is Decode for an in-memory body.
func DecodeBytes(body []byte, v any) error {
	if len(bytes.TrimSpace(body)) == 0 {
		body = []byte("{}")
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	if err := dec.Decode(v); err != nil {
		var te *json.UnmarshalTypeError
		if errors.As(err, &te) {
			return apierr.Serialization("Start of structure or map found where not expected")
		}
		return apierr.Serialization("%s", err.Error())
	}
	return nil
}
