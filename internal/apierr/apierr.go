// Package apierr defines the Secrets Manager (AWS JSON 1.1) error types and their HTTP status.
//
// Every handler returns *Error (or an error wrapping one); anything else is reported to the
// client as InternalServiceError and logged.
package apierr

import (
	"errors"
	"fmt"
	"net/http"
)

// Error is an AWS-style API error. Code is the bare exception name (the "__type").
type Error struct {
	Code    string
	Message string
	Status  int
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

// Is lets errors.Is match on Code: errors.Is(err, apierr.ResourceNotFound("")) is true for any
// ResourceNotFoundException.
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	return ok && t.Code == e.Code
}

// As returns the *Error in err's chain, or nil.
func As(err error) *Error {
	var e *Error
	if errors.As(err, &e) {
		return e
	}
	return nil
}

func newf(code string, status int, format string, args ...any) *Error {
	msg := format
	if len(args) > 0 {
		msg = fmt.Sprintf(format, args...)
	}
	return &Error{Code: code, Message: msg, Status: status}
}

// Secrets Manager service exceptions (service-2.json).
const (
	CodeResourceNotFound      = "ResourceNotFoundException"
	CodeInvalidParameter      = "InvalidParameterException"
	CodeInvalidRequest        = "InvalidRequestException"
	CodeInvalidNextToken      = "InvalidNextTokenException"
	CodeResourceExists        = "ResourceExistsException"
	CodeLimitExceeded         = "LimitExceededException"
	CodeMalformedPolicy       = "MalformedPolicyDocumentException"
	CodePreconditionNotMet    = "PreconditionNotMetException"
	CodePublicPolicy          = "PublicPolicyException"
	CodeDecryptionFailure     = "DecryptionFailure"
	CodeEncryptionFailure     = "EncryptionFailure"
	CodeInternalServiceError  = "InternalServiceError"
	CodeValidation            = "ValidationException"
	CodeSerialization         = "SerializationException"
	CodeUnknownOperation      = "UnknownOperationException"
	CodeAccessDenied          = "AccessDeniedException"
	CodeUnrecognizedClient    = "UnrecognizedClientException"
	CodeInvalidSignature      = "InvalidSignatureException"
	CodeIncompleteSignature   = "IncompleteSignature"
	CodeMissingAuthToken      = "MissingAuthenticationTokenException"
	CodeSignatureDoesNotMatch = "SignatureDoesNotMatch"
	CodeThrottling            = "ThrottlingException"
	CodeRequestExpired        = "RequestExpired"
	CodeInvalidAction         = "InvalidAction"
)

func ResourceNotFound(format string, a ...any) *Error {
	return newf(CodeResourceNotFound, http.StatusBadRequest, format, a...)
}
func InvalidParameter(format string, a ...any) *Error {
	return newf(CodeInvalidParameter, http.StatusBadRequest, format, a...)
}
func InvalidRequest(format string, a ...any) *Error {
	return newf(CodeInvalidRequest, http.StatusBadRequest, format, a...)
}
func InvalidNextToken(format string, a ...any) *Error {
	return newf(CodeInvalidNextToken, http.StatusBadRequest, format, a...)
}
func ResourceExists(format string, a ...any) *Error {
	return newf(CodeResourceExists, http.StatusBadRequest, format, a...)
}
func LimitExceeded(format string, a ...any) *Error {
	return newf(CodeLimitExceeded, http.StatusBadRequest, format, a...)
}
func MalformedPolicy(format string, a ...any) *Error {
	return newf(CodeMalformedPolicy, http.StatusBadRequest, format, a...)
}
func PreconditionNotMet(format string, a ...any) *Error {
	return newf(CodePreconditionNotMet, http.StatusBadRequest, format, a...)
}
func PublicPolicy(format string, a ...any) *Error {
	return newf(CodePublicPolicy, http.StatusBadRequest, format, a...)
}
func DecryptionFailure(format string, a ...any) *Error {
	return newf(CodeDecryptionFailure, http.StatusBadRequest, format, a...)
}
func EncryptionFailure(format string, a ...any) *Error {
	return newf(CodeEncryptionFailure, http.StatusBadRequest, format, a...)
}
func Internal(format string, a ...any) *Error {
	return newf(CodeInternalServiceError, http.StatusInternalServerError, format, a...)
}

// Validation is the protocol-level constraint error (length, pattern, range, required) that
// AWS returns before reaching the service, e.g.
// "1 validation error detected: Value null at 'secretId' failed to satisfy constraint: Member must not be null".
func Validation(format string, a ...any) *Error {
	return newf(CodeValidation, http.StatusBadRequest, format, a...)
}
func Serialization(format string, a ...any) *Error {
	return newf(CodeSerialization, http.StatusBadRequest, format, a...)
}
func UnknownOperation(format string, a ...any) *Error {
	return newf(CodeUnknownOperation, http.StatusBadRequest, format, a...)
}
func AccessDenied(format string, a ...any) *Error {
	return newf(CodeAccessDenied, http.StatusBadRequest, format, a...)
}
func UnrecognizedClient(format string, a ...any) *Error {
	return newf(CodeUnrecognizedClient, http.StatusBadRequest, format, a...)
}
func InvalidSignature(format string, a ...any) *Error {
	return newf(CodeInvalidSignature, http.StatusBadRequest, format, a...)
}
func IncompleteSignature(format string, a ...any) *Error {
	return newf(CodeIncompleteSignature, http.StatusBadRequest, format, a...)
}
func MissingAuthToken(format string, a ...any) *Error {
	return newf(CodeMissingAuthToken, http.StatusBadRequest, format, a...)
}
func RequestExpired(format string, a ...any) *Error {
	return newf(CodeRequestExpired, http.StatusBadRequest, format, a...)
}

// ValidationErrors joins constraint violations the way AWS formats them:
// "2 validation errors detected: <a>; <b>".
func ValidationErrors(violations []string) *Error {
	if len(violations) == 0 {
		return nil
	}
	noun := "error"
	if len(violations) > 1 {
		noun = "errors"
	}
	msg := fmt.Sprintf("%d validation %s detected: ", len(violations), noun)
	for i, v := range violations {
		if i > 0 {
			msg += "; "
		}
		msg += v
	}
	return Validation("%s", msg)
}
