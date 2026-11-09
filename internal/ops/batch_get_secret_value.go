package ops

// Contract for BatchGetSecretValue (frozen by the orchestrator; the handler body is the
// implementer's job). Wire shapes follow botocore secretsmanager/2017-10-17/service-2.json.

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"

	"github.com/nathabonfim59/segredium/internal/api"
	"github.com/nathabonfim59/segredium/internal/apierr"
	"github.com/nathabonfim59/segredium/internal/sm"
	"github.com/nathabonfim59/segredium/internal/store"
)

func init() { api.Register("BatchGetSecretValue", batchGetSecretValue) }

type batchGetSecretValueInput struct {
	Filters      []*listFilter `json:"Filters"`
	MaxResults   *int64        `json:"MaxResults"`
	NextToken    *string       `json:"NextToken"`
	SecretIDList []*string     `json:"SecretIdList"`
}

type batchGetSecretValueOutput struct {
	SecretValues []getSecretValueOutput `json:"SecretValues"`
	NextToken    string                 `json:"NextToken,omitempty"`
	Errors       []apiErrorEntry        `json:"Errors,omitempty"`
}

// apiErrorEntry is the ErrorEntry shape of BatchGetSecretValue's Errors member.
type apiErrorEntry struct {
	SecretID  string `json:"SecretId"`
	ErrorCode string `json:"ErrorCode"`
	Message   string `json:"Message"`
}

// batchGetSecretValue retrieves up to 20 secrets by name/ARN or by filters. Individual failures
// never fail the call: they are reported in Errors, exactly like GetSecretValue would report
// them for that secret.
// https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_BatchGetSecretValue.html
func batchGetSecretValue(ctx context.Context, d *sm.Deps, r *api.Request) (any, error) {
	var in batchGetSecretValueInput
	if err := r.Decode(&in); err != nil {
		return nil, err
	}
	if err := in.validate(); err != nil {
		return nil, err
	}
	if in.SecretIDList != nil {
		return in.byID(ctx, d, r)
	}
	return in.byFilter(ctx, d, r)
}

func (in *batchGetSecretValueInput) validate() error {
	// AWS requires exactly one of SecretIdList and Filters.
	if (in.SecretIDList == nil) == (in.Filters == nil) {
		return apierr.InvalidParameter("You must specify either SecretIdList or Filters, but not both.")
	}
	// Paging only applies to the Filters form (service-2.json member documentation).
	if in.SecretIDList != nil {
		if in.MaxResults != nil {
			return apierr.InvalidParameter("You can only use MaxResults when you specify Filters.")
		}
		if in.NextToken != nil {
			return apierr.InvalidParameter("You can only use NextToken when you specify Filters.")
		}
	}
	var v sm.Validator
	validateListLength(&v, "secretIdList", len(in.SecretIDList), in.SecretIDList != nil, 1, 20)
	for i, id := range in.SecretIDList {
		member := fmt.Sprintf("secretIdList.%d.member", i+1)
		v.Required(member, id != nil)
		v.Length(member, id, 1, 2048)
	}
	v.Range("maxResults", in.MaxResults, 1, 20)
	v.Length("nextToken", in.NextToken, 1, 4096)
	validateFilters(&v, in.Filters)
	if err := v.Err(); err != nil {
		return err
	}
	return checkFilters(in.Filters)
}

// byID returns the requested secrets in request order, including duplicates.
func (in *batchGetSecretValueInput) byID(ctx context.Context, d *sm.Deps, r *api.Request) (any, error) {
	out := &batchGetSecretValueOutput{SecretValues: make([]getSecretValueOutput, 0, len(in.SecretIDList))}
	for _, id := range in.SecretIDList {
		v, err := readSecretValue(ctx, d, r, *id, &getSecretValueInput{SecretID: id})
		if err != nil {
			out.Errors = append(out.Errors, apiError(*id, err))
			continue
		}
		out.SecretValues = append(out.SecretValues, *v)
	}
	return out, nil
}

// byFilter pages through the accessible, non-deleted secrets matching the filters and fetches
// values only for the requested page.
func (in *batchGetSecretValueInput) byFilter(ctx context.Context, d *sm.Deps, r *api.Request) (any, error) {
	var query [32]byte
	start := uint64(0)
	if in.NextToken != nil {
		query = in.queryHash(d, r)
		var err error
		start, err = decodeListToken(*in.NextToken, query)
		if err != nil {
			return nil, err
		}
	}
	secrets, err := store.ListMeta(ctx, d.Store, r.Region)
	if err != nil {
		return nil, storeError(err)
	}
	filters := compileFilters(in.Filters)
	// Reuse the store's slice; values are fetched per returned secret below.
	n := 0
	for _, s := range secrets {
		if s.Deleted() || !d.CanAccess(r.Identity.UID, s) || !matchesFilters(s, filters) {
			continue
		}
		secrets[n] = s
		n++
	}
	clear(secrets[n:])
	secrets = secrets[:n]
	if start > uint64(n) {
		return nil, invalidListToken()
	}
	limit := 20
	if in.MaxResults != nil {
		limit = int(*in.MaxResults)
	}
	end := min(int(start)+limit, n)
	out := &batchGetSecretValueOutput{SecretValues: make([]getSecretValueOutput, 0, end-int(start))}
	for _, meta := range secrets[int(start):end] {
		v, err := readSecretValue(ctx, d, r, meta.ARN, &getSecretValueInput{SecretID: &meta.ARN})
		if err != nil {
			out.Errors = append(out.Errors, apiError(meta.ARN, err))
			continue
		}
		out.SecretValues = append(out.SecretValues, *v)
	}
	if end < n {
		if in.NextToken == nil {
			query = in.queryHash(d, r)
		}
		out.NextToken = encodeListToken(uint64(end), query)
	}
	return out, nil
}

func apiError(secretID string, err error) apiErrorEntry {
	if e := apierr.As(err); e != nil {
		return apiErrorEntry{SecretID: secretID, ErrorCode: e.Code, Message: e.Message}
	}
	return apiErrorEntry{SecretID: secretID, ErrorCode: apierr.CodeInternalServiceError, Message: "An error occurred on the server side."}
}

func (in *batchGetSecretValueInput) queryHash(d *sm.Deps, r *api.Request) [32]byte {
	h := sha256.New()
	// Bind continuation to the filters and caller; page size may change between calls.
	_ = json.NewEncoder(h).Encode(struct {
		Region, Account, AccessMode string
		UID                         *uint32
		Filters                     []*listFilter
	}{r.Region, d.AccountID(), d.Config.Server.AccessMode, r.Identity.UID, in.Filters})
	return [32]byte(h.Sum(nil))
}
