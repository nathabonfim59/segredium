package ops_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/nathabonfim59/segredium/internal/api"
	"github.com/nathabonfim59/segredium/internal/model"
	"github.com/nathabonfim59/segredium/internal/store"
)

func listedNames(t *testing.T, out map[string]any) []string {
	t.Helper()
	entries, ok := out["SecretList"].([]any)
	if !ok {
		t.Fatalf("SecretList is not an array: %#v", out)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.(map[string]any)["Name"].(string))
	}
	return names
}

func TestListSecretsWire(t *testing.T) {
	d := testDeps()
	assertJSON(t, callOK(t, d, region, "ListSecrets", `{}`), map[string]any{"SecretList": []any{}})
	s := seedMetadata(t, d, "secret", func(s *model.Secret) {
		s.Description, s.KmsKeyID, s.Type = "description", model.DefaultKMSKeyID, "partner"
		s.RotationRules = &model.RotationRules{}
		now, later := d.Now(), d.Now().Add(30*24*time.Hour)
		s.LastAccessedDate, s.DeletedDate, s.DeletionDate = &now, &now, &later
		s.LastChangedDate, s.LastRotatedDate, s.NextRotationDate = &now, &now, &later
		s.ExternalSecretRotationMetadata = []model.Tag{{Key: "key", Value: "value"}}
		s.ExternalSecretRotationRoleArn = "arn:aws:iam::123456789012:role/rotation"
		s.Tags = []model.Tag{{Key: "Environment", Value: "Production"}}
		s.OwningService, s.PrimaryRegion = "rds", region
		uid := uint32(1000)
		s.OwnerUID = &uid
		s.Replicas = []model.ReplicationStatus{{Region: "us-west-2", Status: "InSync"}}
		s.Versions = []*model.Version{{VersionID: token1, Stages: []string{"AWSCURRENT"}}, {VersionID: token2}}
	})
	assertJSON(t, callOK(t, d, region, "ListSecrets", `{}`), map[string]any{"SecretList": []any{}})
	want := minimalMetadata(s)
	want["Description"], want["Type"], want["Tags"] = s.Description, s.Type, s.Tags
	want["RotationEnabled"], want["RotationRules"] = false, map[string]any{}
	want["LastAccessedDate"], want["DeletedDate"] = model.Day(*s.LastAccessedDate).Unix(), epoch(*s.DeletedDate)
	want["LastChangedDate"], want["LastRotatedDate"], want["NextRotationDate"] = epoch(*s.LastChangedDate), epoch(*s.LastRotatedDate), epoch(*s.NextRotationDate)
	want["ExternalSecretRotationMetadata"], want["ExternalSecretRotationRoleArn"] = s.ExternalSecretRotationMetadata, s.ExternalSecretRotationRoleArn
	want["OwningService"], want["PrimaryRegion"] = s.OwningService, s.PrimaryRegion
	want["SecretVersionsToStages"] = map[string][]string{token1: {"AWSCURRENT"}}
	assertJSON(t, callOK(t, d, region, "ListSecrets", `{"IncludePlannedDeletion":true}`), map[string]any{"SecretList": []any{want}})
	assertJSON(t, callOK(t, d, "us-west-2", "ListSecrets", `{}`), map[string]any{"SecretList": []any{}})
	if !reflect.DeepEqual(s, stored(t, d, s.Name)) {
		t.Fatal("ListSecrets changed stored state")
	}
}

func TestListSecretsFilters(t *testing.T) {
	for _, tc := range []struct {
		name, key string
		values    []string
		match     bool
	}{
		{"name prefix", "name", []string{"Prod"}, true},
		{"name case", "name", []string{"prod"}, false},
		{"name not substring", "name", []string{"Database"}, false},
		{"description case", "description", []string{"production D"}, true},
		{"description prefix", "description", []string{"database"}, false},
		{"tag key", "tag-key", []string{"Environ"}, true},
		{"tag key case", "tag-key", []string{"environ"}, false},
		{"tag value", "tag-value", []string{"Prod"}, true},
		{"tag value case", "tag-value", []string{"prod"}, false},
		{"primary region", "primary-region", []string{"us-east"}, true},
		{"primary region case", "primary-region", []string{"US-east"}, false},
		{"owning service", "owning-service", []string{"rds"}, true},
		{"owning service case", "owning-service", []string{"RDS"}, false},
		{"negation includes", "name", []string{"!Test"}, true},
		{"negation excludes", "name", []string{"!Prod"}, false},
		{"values use OR", "name", []string{"Other", "Prod"}, true},
		{"all name words", "all", []string{"database"}, true},
		{"all tag words", "all", []string{"PRODUCTION"}, true},
		{"all tag key", "all", []string{"ENVIRONMENT"}, true},
		{"all description", "all", []string{"Credentials"}, true},
		{"all words use OR", "all", []string{"absent/Credentials"}, true},
		{"all camel case and numbers", "all", []string{"otherDatabase892"}, true},
		{"all negated", "all", []string{"!Credentials"}, false},
		{"all excludes substring", "all", []string{"data"}, false},
		{"empty prefix", "name", []string{""}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := testDeps()
			seedMetadata(t, d, "ProdDatabase892", func(s *model.Secret) {
				s.Description = "Production Database Credentials"
				s.Tags = []model.Tag{{Key: "Environment", Value: "Production"}}
				s.PrimaryRegion, s.OwningService = region, "rds.amazonaws.com"
			})
			out := callOK(t, d, region, "ListSecrets", map[string]any{"Filters": []map[string]any{{"Key": tc.key, "Values": tc.values}}})
			names := listedNames(t, out)
			if (len(names) == 1) != tc.match {
				t.Fatalf("names %v, want match %v", names, tc.match)
			}
		})
	}
	d := testDeps()
	seedMetadata(t, d, "Production", nil)
	out := callOK(t, d, region, "ListSecrets", map[string]any{"Filters": []map[string]any{
		{"Key": "name", "Values": []string{"Prod"}}, {"Key": "description", "Values": []string{"missing"}},
	}})
	if len(listedNames(t, out)) != 0 {
		t.Fatal("filters must use AND")
	}
}

func TestListSecretsSort(t *testing.T) {
	d := testDeps()
	for i, name := range []string{"charlie", "alpha", "bravo"} {
		seedMetadata(t, d, name, func(s *model.Secret) {
			s.CreatedDate = d.Now().Add(time.Duration(i) * time.Hour)
			if i != 1 {
				tm := d.Now().Add(time.Duration(2-i) * time.Hour)
				s.LastAccessedDate, s.LastChangedDate = &tm, &tm
			}
		})
	}
	for _, tc := range []struct {
		key, order string
		want       []string
	}{
		{"", "", []string{"charlie", "alpha", "bravo"}},
		{"created-date", "desc", []string{"bravo", "alpha", "charlie"}},
		{"name", "asc", []string{"alpha", "bravo", "charlie"}},
		{"name", "desc", []string{"charlie", "bravo", "alpha"}},
		{"last-accessed-date", "asc", []string{"alpha", "bravo", "charlie"}},
		{"last-changed-date", "desc", []string{"charlie", "bravo", "alpha"}},
	} {
		t.Run(tc.key+tc.order, func(t *testing.T) {
			in := map[string]any{}
			if tc.key != "" {
				in["SortBy"] = tc.key
			}
			if tc.order != "" {
				in["SortOrder"] = tc.order
			}
			if got := listedNames(t, callOK(t, d, region, "ListSecrets", in)); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("names %v, want %v", got, tc.want)
			}
		})
	}
}

func TestListSecretsPagination(t *testing.T) {
	d := testDeps()
	for i := range 103 {
		seedMetadata(t, d, fmt.Sprintf("secret/%03d", i), nil)
	}
	first := callOK(t, d, region, "ListSecrets", `{}`)
	if len(listedNames(t, first)) != 100 || first["NextToken"] == nil {
		t.Fatalf("default page: %#v", first)
	}
	last := callOK(t, d, region, "ListSecrets", map[string]any{"NextToken": first["NextToken"]})
	if got := listedNames(t, last); !reflect.DeepEqual(got, []string{"secret/100", "secret/101", "secret/102"}) || last["NextToken"] != nil {
		t.Fatalf("last page: %#v", last)
	}
	first = callOK(t, d, region, "ListSecrets", `{"MaxResults":1,"SortBy":"name","SortOrder":"desc","Filters":[{"Key":"name","Values":["secret/10"]}]}`)
	if got := listedNames(t, first); !reflect.DeepEqual(got, []string{"secret/102"}) {
		t.Fatalf("first filtered page: %#v", first)
	}
	query := map[string]any{"MaxResults": 100, "SortBy": "name", "SortOrder": "desc", "Filters": []map[string]any{{"Key": "name", "Values": []string{"secret/10"}}}, "NextToken": first["NextToken"]}
	last = callOK(t, d, region, "ListSecrets", query)
	if got := listedNames(t, last); !reflect.DeepEqual(got, []string{"secret/101", "secret/100"}) || last["NextToken"] != nil {
		t.Fatalf("filtered final page: %#v", last)
	}
	callError(t, d, "ListSecrets", map[string]any{"NextToken": first["NextToken"]}, "InvalidNextTokenException", "The NextToken value is invalid.")
	status, body := api.TestCall(d, "us-west-2", "ListSecrets", map[string]any{"NextToken": first["NextToken"]})
	if status != 400 || api.ErrorType(body) != "InvalidNextTokenException" {
		t.Fatalf("cross-region token: %d %s", status, body)
	}
}

func TestListSecretsInvalidTokens(t *testing.T) {
	d := testDeps()
	seedMetadata(t, d, "a", nil)
	seedMetadata(t, d, "b", nil)
	out := callOK(t, d, region, "ListSecrets", `{"MaxResults":1}`)
	token := out["NextToken"].(string)
	decoded, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		t.Fatal(err)
	}
	decoded[len(decoded)-1] ^= 1
	for _, value := range []string{"garbage", strings.Repeat("a", 4096), token + "A", base64.RawURLEncoding.EncodeToString(decoded)} {
		t.Run(fmt.Sprintf("length-%d", len(value)), func(t *testing.T) {
			callError(t, d, "ListSecrets", map[string]any{"NextToken": value}, "InvalidNextTokenException", "The NextToken value is invalid.")
		})
	}
}

func TestListSecretsValidation(t *testing.T) {
	for _, tc := range []struct{ input, code string }{
		{`{"MaxResults":0}`, "ValidationException"},
		{`{"MaxResults":101}`, "ValidationException"},
		{`{"MaxResults":1.5}`, "SerializationException"},
		{`{"NextToken":""}`, "ValidationException"},
		{`{"SortOrder":"ASC"}`, "ValidationException"},
		{`{"SortOrder":""}`, "ValidationException"},
		{`{"SortBy":"Name"}`, "ValidationException"},
		{`{"SortBy":""}`, "ValidationException"},
		{`{"Filters":[null]}`, "ValidationException"},
		{`{"Filters":[{}]}`, "InvalidParameterException"},
		{`{"Filters":[{"Key":"invalid","Values":["a"]}]}`, "ValidationException"},
		{`{"Filters":[{"Key":"","Values":["a"]}]}`, "ValidationException"},
		{`{"Filters":[{"Key":"name","Values":[]}]}`, "ValidationException"},
		{`{"Filters":[{"Key":"name"}]}`, "InvalidParameterException"},
		{`{"Filters":[{"Key":"name","Values":[null]}]}`, "ValidationException"},
		{`{"Filters":[{"Key":"name","Values":["bad*pattern"]}]}`, "ValidationException"},
		{`{"IncludePlannedDeletion":"true"}`, "SerializationException"},
	} {
		t.Run(tc.input, func(t *testing.T) { callError(t, testDeps(), "ListSecrets", tc.input, tc.code, "") })
	}
	callError(t, testDeps(), "ListSecrets", map[string]any{"NextToken": strings.Repeat("a", 4097)}, "ValidationException", "")
	callError(t, testDeps(), "ListSecrets", map[string]any{"Filters": []map[string]any{{"Key": "name", "Values": []string{strings.Repeat("a", 513)}}}}, "ValidationException", "")
	filters := make([]map[string]any, 11)
	for i := range filters {
		filters[i] = map[string]any{"Key": "name", "Values": []string{"a"}}
	}
	callError(t, testDeps(), "ListSecrets", map[string]any{"Filters": filters}, "ValidationException", "")
	callError(t, testDeps(), "ListSecrets", map[string]any{"Filters": []map[string]any{{"Key": "name", "Values": strings.Fields(strings.Repeat("a ", 11))}}}, "ValidationException", "")
}

func TestListSecretsAccess(t *testing.T) {
	d := testDeps()
	d.Config.Server.AccessMode = "owner"
	owner, other, root := uint32(1000), uint32(1001), uint32(0)
	seedMetadata(t, d, "a-other", func(s *model.Secret) { s.OwnerUID = &other })
	seedMetadata(t, d, "b-owned", func(s *model.Secret) { s.OwnerUID = &owner })
	seedMetadata(t, d, "c-unowned", nil)
	seedMetadata(t, d, "d-owned", func(s *model.Secret) { s.OwnerUID = &owner })
	for _, tc := range []struct {
		name string
		uid  *uint32
		want []string
	}{
		{"owner", &owner, []string{"b-owned", "d-owned"}},
		{"other", &other, []string{"a-other"}},
		{"root", &root, []string{"a-other", "b-owned", "c-unowned", "d-owned"}},
		{"unknown", nil, []string{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status, body := callAsUID(t, d, tc.uid, "ListSecrets", map[string]any{"SortBy": "name"})
			if status != 200 {
				t.Fatalf("list: %d %s", status, body)
			}
			var out map[string]any
			if err := json.Unmarshal(body, &out); err != nil {
				t.Fatal(err)
			}
			if got := listedNames(t, out); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("names %v, want %v", got, tc.want)
			}
		})
	}
	status, body := callAsUID(t, d, &owner, "ListSecrets", map[string]any{"MaxResults": 1})
	if status != 200 {
		t.Fatalf("first page: %d %s", status, body)
	}
	var first map[string]any
	if err := json.Unmarshal(body, &first); err != nil {
		t.Fatal(err)
	}
	if got := listedNames(t, first); !reflect.DeepEqual(got, []string{"b-owned"}) {
		t.Fatalf("filter access before paging: %#v", first)
	}
	status, body = callAsUID(t, d, &other, "ListSecrets", map[string]any{"NextToken": first["NextToken"]})
	if status != 400 || api.ErrorType(body) != "InvalidNextTokenException" {
		t.Fatalf("cross-caller token: %d %s", status, body)
	}
}

type metadataOnlyStore struct {
	store.Store
	metaCalls int
	region    string
}

func (s *metadataOnlyStore) ListSecrets(context.Context, string) ([]*model.Secret, error) {
	return nil, errors.New("ListSecrets must not copy secret values")
}

func (s *metadataOnlyStore) ListSecretsMeta(ctx context.Context, region string) ([]*model.Secret, error) {
	s.metaCalls++
	s.region = region
	return store.ListMeta(ctx, s.Store, region)
}

func TestListSecretsUsesMetadata(t *testing.T) {
	d := testDeps()
	seedMetadata(t, d, "secret", func(s *model.Secret) {
		s.Versions = []*model.Version{{VersionID: token1, SecretBinary: []byte("payload"), Stages: []string{"AWSCURRENT"}}}
	})
	spy := &metadataOnlyStore{Store: d.Store}
	d.Store = spy
	out := callOK(t, d, region, "ListSecrets", `{}`)
	if spy.metaCalls != 1 || spy.region != region || !reflect.DeepEqual(listedNames(t, out), []string{"secret"}) {
		t.Fatalf("metadata listing: calls=%d region=%s output=%#v", spy.metaCalls, spy.region, out)
	}
}
