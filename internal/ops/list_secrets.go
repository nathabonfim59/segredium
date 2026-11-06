package ops

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/nathabonfim59/segredium/internal/api"
	"github.com/nathabonfim59/segredium/internal/apierr"
	"github.com/nathabonfim59/segredium/internal/model"
	"github.com/nathabonfim59/segredium/internal/sm"
	"github.com/nathabonfim59/segredium/internal/store"
)

func init() { api.Register("ListSecrets", listSecrets) }

type listSecretsInput struct {
	IncludePlannedDeletion bool          `json:"IncludePlannedDeletion"`
	MaxResults             *int64        `json:"MaxResults"`
	NextToken              *string       `json:"NextToken"`
	Filters                []*listFilter `json:"Filters"`
	SortOrder              *string       `json:"SortOrder"`
	SortBy                 *string       `json:"SortBy"`
}

type listFilter struct {
	Key    *string   `json:"Key"`
	Values []*string `json:"Values"`
}

type listSecretsOutput struct {
	SecretList []secretListEntry `json:"SecretList"`
	NextToken  string            `json:"NextToken,omitempty"`
}

type secretListEntry struct {
	secretMetadata
	SecretVersionsToStages map[string][]string `json:"SecretVersionsToStages,omitempty"`
}

func listSecrets(ctx context.Context, d *sm.Deps, r *api.Request) (any, error) {
	var in listSecretsInput
	if err := r.Decode(&in); err != nil {
		return nil, err
	}
	if err := in.validate(); err != nil {
		return nil, err
	}
	if in.SortBy == nil {
		in.SortBy = new("created-date")
	}
	if in.SortOrder == nil {
		in.SortOrder = new("asc")
	}
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
	// Reuse the store's slice and build version maps only for the requested page.
	n := 0
	for _, s := range secrets {
		if (!in.IncludePlannedDeletion && s.Deleted()) || !d.CanAccess(r.Identity.UID, s) || !matchesFilters(s, filters) {
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
	if *in.SortBy == "created-date" {
		// Stores already return CreatedDate ascending, including the ARN tie-break.
		if *in.SortOrder == "desc" {
			slices.Reverse(secrets)
		}
	} else {
		slices.SortFunc(secrets, func(a, b *model.Secret) int {
			c := compareSecrets(a, b, *in.SortBy)
			if *in.SortOrder == "desc" {
				return -c
			}
			return c
		})
	}
	limit := 100
	if in.MaxResults != nil {
		limit = int(*in.MaxResults)
	}
	end := min(int(start)+limit, n)
	out := &listSecretsOutput{SecretList: make([]secretListEntry, 0, end-int(start))}
	for _, s := range secrets[int(start):end] {
		out.SecretList = append(out.SecretList, secretListEntry{secretMetadata: metadata(s), SecretVersionsToStages: labeledVersions(s)})
	}
	if end < n {
		if in.NextToken == nil {
			query = in.queryHash(d, r)
		}
		out.NextToken = encodeListToken(uint64(end), query)
	}
	return out, nil
}

func (in *listSecretsInput) validate() error {
	var v sm.Validator
	v.Range("maxResults", in.MaxResults, 1, 100)
	v.Length("nextToken", in.NextToken, 1, 4096)
	validateEnum(&v, "sortOrder", in.SortOrder, []string{"asc", "desc"})
	validateEnum(&v, "sortBy", in.SortBy, []string{"created-date", "last-accessed-date", "last-changed-date", "name"})
	validateListLength(&v, "filters", len(in.Filters), in.Filters != nil, 0, 10)
	for i, filter := range in.Filters {
		member := fmt.Sprintf("filters.%d.member", i+1)
		v.Required(member, filter != nil)
		if filter == nil {
			continue
		}
		validateEnum(&v, member+".key", filter.Key, []string{"description", "name", "tag-key", "tag-value", "primary-region", "owning-service", "all"})
		validateListLength(&v, member+".values", len(filter.Values), filter.Values != nil, 1, 10)
		for j, value := range filter.Values {
			field := fmt.Sprintf("%s.values.%d.member", member, j+1)
			v.Required(field, value != nil)
			v.Length(field, value, 0, 512)
			if value != nil && !validFilterValue(*value) {
				v.Custom(fmt.Sprintf("Value '%s' at '%s' failed to satisfy constraint: Member must satisfy regular expression pattern: ^\\!?[a-zA-Z0-9 :_@\\/\\+\\=\\.\\-\\!]*$", *value, field))
			}
		}
	}
	if err := v.Err(); err != nil {
		return err
	}
	for _, filter := range in.Filters {
		if filter.Key == nil || len(filter.Values) == 0 {
			return apierr.InvalidParameter("The filter must include a key and at least one value.")
		}
	}
	return nil
}

func validateEnum(v *sm.Validator, member string, value *string, values []string) {
	if value != nil && !slices.Contains(values, *value) {
		v.Custom(fmt.Sprintf("Value '%s' at '%s' failed to satisfy constraint: Member must satisfy enum value set: [%s]", *value, member, strings.Join(values, ", ")))
	}
}

func validateListLength(v *sm.Validator, member string, length int, present bool, low, high int) {
	if !present {
		return
	}
	if length < low {
		v.Custom(fmt.Sprintf("Value at '%s' failed to satisfy constraint: Member must have length greater than or equal to %d", member, low))
	}
	if length > high {
		v.Custom(fmt.Sprintf("Value at '%s' failed to satisfy constraint: Member must have length less than or equal to %d", member, high))
	}
}

func validFilterValue(value string) bool {
	for _, c := range value {
		if !asciiLetter(c) && (c < '0' || c > '9') && !strings.ContainsRune(" :_@/+=.-!", c) {
			return false
		}
	}
	return true
}

type compiledFilter struct {
	key    string
	values []filterValue
}

type filterValue struct {
	text   string
	negate bool
	words  []string
}

func compileFilters(filters []*listFilter) []compiledFilter {
	out := make([]compiledFilter, 0, len(filters))
	for _, f := range filters {
		c := compiledFilter{key: *f.Key, values: make([]filterValue, 0, len(f.Values))}
		for _, value := range f.Values {
			text, negate := strings.CutPrefix(*value, "!")
			v := filterValue{text: text, negate: negate}
			if *f.Key == "description" || *f.Key == "all" {
				v.text = strings.ToLower(text)
			}
			if *f.Key == "all" {
				v.words = searchWords(text)
			}
			c.values = append(c.values, v)
		}
		out = append(out, c)
	}
	return out
}

func matchesFilters(s *model.Secret, filters []compiledFilter) bool {
	for _, filter := range filters {
		matched := false
		for _, value := range filter.values {
			if matchFilterValue(s, filter.key, value) != value.negate {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

func matchFilterValue(s *model.Secret, key string, value filterValue) bool {
	// API_Filter defines case-sensitive prefixes except for description and all.
	// https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_Filter.html
	switch key {
	case "name":
		return strings.HasPrefix(s.Name, value.text)
	case "description":
		return len(s.Description) >= len(value.text) && strings.EqualFold(s.Description[:len(value.text)], value.text)
	case "primary-region":
		return strings.HasPrefix(s.PrimaryRegion, value.text)
	case "owning-service":
		return strings.HasPrefix(s.OwningService, value.text)
	case "tag-key", "tag-value":
		for _, tag := range s.Tags {
			text := tag.Key
			if key == "tag-value" {
				text = tag.Value
			}
			if strings.HasPrefix(text, value.text) {
				return true
			}
		}
	case "all":
		if matchWords(s.Name, value.words) || matchWords(s.Description, value.words) {
			return true
		}
		for _, tag := range s.Tags {
			if matchWords(tag.Key, value.words) || matchWords(tag.Value, value.words) {
				return true
			}
		}
	}
	return false
}

func asciiLetter(c rune) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }

// The Secrets Manager search guide splits words at punctuation, digit/letter
// boundaries and camel case, then matches any word without case sensitivity.
// https://docs.aws.amazon.com/secretsmanager/latest/userguide/manage_search-secret.html
func searchWords(text string) []string {
	var words []string
	for start, end := 0, 0; end <= len(text); end++ {
		if end == len(text) || !wordByte(text[end]) {
			if start < end {
				words = append(words, strings.ToLower(text[start:end]))
			}
			start = end + 1
		} else if start < end && wordBoundary(text, end) {
			words = append(words, strings.ToLower(text[start:end]))
			start = end
		}
	}
	return words
}

func wordByte(c byte) bool { return asciiLetter(rune(c)) || c >= '0' && c <= '9' }

func wordBoundary(s string, i int) bool {
	a, b := s[i-1], s[i]
	if (a >= '0' && a <= '9') != (b >= '0' && b <= '9') {
		return true
	}
	return a >= 'a' && a <= 'z' && b >= 'A' && b <= 'Z' ||
		a >= 'A' && a <= 'Z' && b >= 'A' && b <= 'Z' && i+1 < len(s) && s[i+1] >= 'a' && s[i+1] <= 'z'
}

func matchWords(text string, words []string) bool {
	// Scan words without allocating a per-secret token slice.
	for start, end := 0, 0; end <= len(text); end++ {
		boundary := end == len(text) || !wordByte(text[end])
		if boundary || start < end && wordBoundary(text, end) {
			for _, word := range words {
				if start < end && strings.EqualFold(text[start:end], word) {
					return true
				}
			}
			start = end
			if boundary {
				start++
			}
		}
	}
	return false
}

func compareSecrets(a, b *model.Secret, key string) int {
	var c int
	switch key {
	case "name":
		c = cmp.Compare(a.Name, b.Name)
	case "last-accessed-date":
		c = compareOptionalTimes(a.LastAccessedDate, b.LastAccessedDate)
	case "last-changed-date":
		c = compareOptionalTimes(a.LastChangedDate, b.LastChangedDate)
	default:
		c = a.CreatedDate.Compare(b.CreatedDate)
	}
	if c == 0 {
		c = cmp.Compare(a.ARN, b.ARN)
	}
	return c
}

func compareOptionalTimes(a, b *time.Time) int {
	if a == nil {
		if b == nil {
			return 0
		}
		return -1
	}
	if b == nil {
		return 1
	}
	return a.Compare(*b)
}

func (in *listSecretsInput) queryHash(d *sm.Deps, r *api.Request) [32]byte {
	h := sha256.New()
	// Bind continuation to the query and caller; page size may change between calls.
	_ = json.NewEncoder(h).Encode(struct {
		Region, Account, AccessMode string
		UID                         *uint32
		IncludeDeleted              bool
		Filters                     []*listFilter
		SortBy, SortOrder           string
	}{r.Region, d.AccountID(), d.Config.Server.AccessMode, r.Identity.UID, in.IncludePlannedDeletion, in.Filters, *in.SortBy, *in.SortOrder})
	return [32]byte(h.Sum(nil))
}

// Tokens are stateless, versioned cursors with a query fingerprint and corruption
// checksum. Every page still independently enforces access and filters.
func encodeListToken(offset uint64, query [32]byte) string {
	var token [73]byte
	token[0] = 1
	binary.BigEndian.PutUint64(token[1:9], offset)
	copy(token[9:41], query[:])
	checksum := sha256.Sum256(token[:41])
	copy(token[41:], checksum[:])
	return base64.RawURLEncoding.EncodeToString(token[:])
}

func decodeListToken(value string, query [32]byte) (uint64, error) {
	var token [73]byte
	if len(value) != base64.RawURLEncoding.EncodedLen(len(token)) {
		return 0, invalidListToken()
	}
	n, err := base64.RawURLEncoding.Strict().Decode(token[:], []byte(value))
	if err != nil || n != len(token) || token[0] != 1 || !bytes.Equal(token[9:41], query[:]) {
		return 0, invalidListToken()
	}
	checksum := sha256.Sum256(token[:41])
	offset := binary.BigEndian.Uint64(token[1:9])
	if offset == 0 || !bytes.Equal(token[41:], checksum[:]) {
		return 0, invalidListToken()
	}
	return offset, nil
}

func invalidListToken() error { return apierr.InvalidNextToken("The NextToken value is invalid.") }
