package ops_test

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/nathabonfim59/segredium/internal/api"
	"github.com/nathabonfim59/segredium/internal/model"
	"github.com/nathabonfim59/segredium/internal/sm"
)

func batchEntry(t *testing.T, d *sm.Deps, name, versionID string, value map[string]any) map[string]any {
	t.Helper()
	s := stored(t, d, name)
	v := s.Version(versionID)
	out := map[string]any{"ARN": s.ARN, "Name": s.Name, "VersionId": v.VersionID, "CreatedDate": epoch(v.CreatedDate)}
	if len(v.Stages) > 0 {
		out["VersionStages"] = v.Stages
	}
	for k, val := range value {
		out[k] = val
	}
	return out
}

func TestBatchGetSecretValueWire(t *testing.T) {
	d := testDeps()
	create(t, d, "secret")
	callOK(t, d, region, "CreateSecret", map[string]any{"Name": "binary", "SecretBinary": []byte{0, 1, 255}, "ClientRequestToken": token1})
	s := stored(t, d, "secret")
	partial := s.ARN[:strings.LastIndex(s.ARN, "-")]
	out := callOK(t, d, region, "BatchGetSecretValue", map[string]any{"SecretIdList": []string{"secret", s.ARN, partial, "binary", "secret"}})
	stringValue := map[string]any{"SecretString": "initial"}
	binaryValue := map[string]any{"SecretBinary": []byte{0, 1, 255}}
	assertJSON(t, out, map[string]any{"SecretValues": []any{
		batchEntry(t, d, "secret", token1, stringValue),
		batchEntry(t, d, "secret", token1, stringValue),
		batchEntry(t, d, "secret", token1, stringValue),
		batchEntry(t, d, "binary", token1, binaryValue),
		batchEntry(t, d, "secret", token1, stringValue),
	}})
	// Both the secret and the current version record the access day, like GetSecretValue.
	day := model.Day(d.Now())
	for _, name := range []string{"secret", "binary"} {
		s := stored(t, d, name)
		if s.LastAccessedDate == nil || !s.LastAccessedDate.Equal(day) || s.Version(token1).LastAccessedDate == nil || !s.Version(token1).LastAccessedDate.Equal(day) {
			t.Fatalf("%s access day not recorded", name)
		}
	}
	// An empty Filters list is a valid selector and matches every secret.
	out = callOK(t, d, region, "BatchGetSecretValue", `{"Filters":[]}`)
	if got := len(out["SecretValues"].([]any)); got != 2 || out["Errors"] != nil {
		t.Fatalf("empty filters: %#v", out)
	}
	// Nothing matched: the main list is still an array.
	assertJSON(t, callOK(t, d, region, "BatchGetSecretValue", `{"Filters":[{"Key":"name","Values":["absent"]}]}`), map[string]any{"SecretValues": []any{}})
}

func TestBatchGetSecretValueErrors(t *testing.T) {
	d := testDeps()
	create(t, d, "ok")
	callOK(t, d, region, "CreateSecret", `{"Name":"empty"}`)
	deleted := create(t, d, "deleted")
	if _, err := d.Store.UpdateSecret(context.Background(), region, deleted["ARN"].(string), func(s *model.Secret) error {
		now := d.Now()
		s.DeletedDate = &now
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	out := callOK(t, d, region, "BatchGetSecretValue", map[string]any{"SecretIdList": []string{
		"ok", "missing", "empty", "deleted", "arn:aws:secretsmanager:us-east-1:999999999999:secret:ok",
	}})
	versionNotFound := "Secrets Manager can't find the specified secret value for staging label: AWSCURRENT"
	assertJSON(t, out, map[string]any{
		"SecretValues": []any{batchEntry(t, d, "ok", token1, map[string]any{"SecretString": "initial"})},
		"Errors": []any{
			map[string]any{"SecretId": "missing", "ErrorCode": "ResourceNotFoundException", "Message": sm.MsgNotFound},
			map[string]any{"SecretId": "empty", "ErrorCode": "ResourceNotFoundException", "Message": versionNotFound},
			map[string]any{"SecretId": "deleted", "ErrorCode": "InvalidRequestException", "Message": msgDeletedForTest},
			map[string]any{"SecretId": "arn:aws:secretsmanager:us-east-1:999999999999:secret:ok", "ErrorCode": "ResourceNotFoundException", "Message": sm.MsgNotFound},
		},
	})
	if stored(t, d, "empty").LastAccessedDate != nil {
		t.Fatal("failed secret recorded access")
	}
	if out := callOK(t, d, region, "BatchGetSecretValue", `{"SecretIdList":["missing"]}`); len(out["SecretValues"].([]any)) != 0 || len(out["Errors"].([]any)) != 1 {
		t.Fatalf("all-failing batch: %#v", out)
	}
}

const msgDeletedForTest = "You can't perform this operation on the secret because it was marked for deletion."

func TestBatchGetSecretValueFilters(t *testing.T) {
	d := testDeps()
	for _, name := range []string{"team/a", "team/b", "team/c", "other"} {
		name := name
		seedMetadata(t, d, name, func(s *model.Secret) {
			value := "value-" + name
			s.Versions = []*model.Version{{VersionID: token1, SecretString: &value, Stages: []string{model.StageCurrent}, CreatedDate: d.Now()}}
		})
	}
	seedMetadata(t, d, "team/deleted", func(s *model.Secret) {
		value := "value-deleted"
		now := d.Now()
		s.DeletedDate = &now
		s.Versions = []*model.Version{{VersionID: token1, SecretString: &value, Stages: []string{model.StageCurrent}, CreatedDate: now}}
	})
	spy := &metadataOnlyStore{Store: d.Store}
	d.Store = spy
	filters := []map[string]any{{"Key": "name", "Values": []string{"team/"}}}
	first := callOK(t, d, region, "BatchGetSecretValue", map[string]any{"Filters": filters, "MaxResults": 2})
	if spy.metaCalls != 1 || spy.region != region {
		t.Fatalf("metadata listing: calls=%d region=%s", spy.metaCalls, spy.region)
	}
	if got := len(first["SecretValues"].([]any)); got != 2 || first["NextToken"] == nil || first["Errors"] != nil {
		t.Fatalf("first page: %#v", first)
	}
	values := func(out map[string]any) []string {
		var names []string
		for _, entry := range out["SecretValues"].([]any) {
			names = append(names, entry.(map[string]any)["Name"].(string))
		}
		return names
	}
	if got := values(first); !reflect.DeepEqual(got, []string{"team/a", "team/b"}) {
		t.Fatalf("first page names %v", got)
	}
	if first["SecretValues"].([]any)[0].(map[string]any)["SecretString"] != "value-team/a" {
		t.Fatal("filtered page must return the secret value")
	}
	rest := callOK(t, d, region, "BatchGetSecretValue", map[string]any{"Filters": filters, "NextToken": first["NextToken"]})
	if got := values(rest); !reflect.DeepEqual(got, []string{"team/c"}) || rest["NextToken"] != nil {
		t.Fatalf("last page: %#v", rest)
	}
	// Access day recorded for returned secrets only.
	day := model.Day(d.Now())
	if s := stored(t, d, "team/a"); s.LastAccessedDate == nil || !s.LastAccessedDate.Equal(day) {
		t.Fatal("filtered value did not record access")
	}
	if stored(t, d, "team/deleted").LastAccessedDate != nil {
		t.Fatal("deleted secret was read")
	}
	// Tokens are bound to the query, caller and region.
	callError(t, d, "BatchGetSecretValue", map[string]any{"Filters": []map[string]any{{"Key": "name", "Values": []string{"other"}}}, "NextToken": first["NextToken"]}, "InvalidNextTokenException", "The NextToken value is invalid.")
	status, body := api.TestCall(d, "us-west-2", "BatchGetSecretValue", map[string]any{"Filters": filters, "NextToken": first["NextToken"]})
	if status != 400 || api.ErrorType(body) != "InvalidNextTokenException" {
		t.Fatalf("cross-region token: %d %s", status, body)
	}
	callError(t, d, "BatchGetSecretValue", map[string]any{"SecretIdList": []string{"team/a"}, "NextToken": first["NextToken"]}, "InvalidParameterException", "")
}

func TestBatchGetSecretValueDefaultPageSize(t *testing.T) {
	d := testDeps()
	for i := range 25 {
		name := fmt.Sprintf("page/%02d", i)
		seedMetadata(t, d, name, func(s *model.Secret) {
			value := name
			s.Versions = []*model.Version{{VersionID: token1, SecretString: &value, Stages: []string{model.StageCurrent}, CreatedDate: d.Now()}}
		})
	}
	seen := map[string]bool{}
	out := callOK(t, d, region, "BatchGetSecretValue", `{"Filters":[]}`)
	for page := 0; ; page++ {
		if len(out["SecretValues"].([]any)) > 20 {
			t.Fatalf("page has more than 20 values: %d", len(out["SecretValues"].([]any)))
		}
		for _, entry := range out["SecretValues"].([]any) {
			seen[entry.(map[string]any)["Name"].(string)] = true
		}
		token, ok := out["NextToken"].(string)
		if !ok {
			break
		}
		if page == 0 && len(out["SecretValues"].([]any)) != 20 {
			t.Fatalf("default page size = %d, want 20", len(out["SecretValues"].([]any)))
		}
		out = callOK(t, d, region, "BatchGetSecretValue", map[string]any{"Filters": []map[string]any{}, "NextToken": token})
	}
	if len(seen) != 25 {
		t.Fatalf("paged through %d secrets, want 25", len(seen))
	}
}

func TestBatchGetSecretValueValidation(t *testing.T) {
	for _, tc := range []struct{ name, input, code string }{
		{"neither", `{}`, "InvalidParameterException"},
		{"both", `{"SecretIdList":["a"],"Filters":[]}`, "InvalidParameterException"},
		{"empty id list", `{"SecretIdList":[]}`, "ValidationException"},
		{"null id", `{"SecretIdList":[null]}`, "ValidationException"},
		{"empty id", `{"SecretIdList":[""]}`, "ValidationException"},
		{"long id", `{"SecretIdList":["` + strings.Repeat("a", 2049) + `"]}`, "ValidationException"},
		{"max results with ids", `{"SecretIdList":["a"],"MaxResults":1}`, "InvalidParameterException"},
		{"next token with ids", `{"SecretIdList":["a"],"NextToken":"x"}`, "InvalidParameterException"},
		{"max results low", `{"Filters":[],"MaxResults":0}`, "ValidationException"},
		{"max results high", `{"Filters":[],"MaxResults":21}`, "ValidationException"},
		{"next token empty", `{"Filters":[],"NextToken":""}`, "ValidationException"},
		{"max results without selector", `{"MaxResults":1}`, "InvalidParameterException"},
		{"bad filter key", `{"Filters":[{"Key":"invalid","Values":["a"]}]}`, "ValidationException"},
		{"filter without values", `{"Filters":[{"Key":"name"}]}`, "InvalidParameterException"},
		{"null filter", `{"Filters":[null]}`, "ValidationException"},
		{"id list wrong type", `{"SecretIdList":"a"}`, "SerializationException"},
	} {
		t.Run(tc.name, func(t *testing.T) { callError(t, testDeps(), "BatchGetSecretValue", tc.input, tc.code, "") })
	}
	ids := make([]string, 21)
	for i := range ids {
		ids[i] = fmt.Sprintf("secret-%d", i)
	}
	callError(t, testDeps(), "BatchGetSecretValue", map[string]any{"SecretIdList": ids}, "ValidationException", "")
	callError(t, testDeps(), "BatchGetSecretValue", map[string]any{"Filters": []map[string]any{}, "NextToken": strings.Repeat("a", 4097)}, "ValidationException", "")
	filters := make([]map[string]any, 11)
	for i := range filters {
		filters[i] = map[string]any{"Key": "name", "Values": []string{"a"}}
	}
	callError(t, testDeps(), "BatchGetSecretValue", map[string]any{"Filters": filters}, "ValidationException", "")
	callError(t, testDeps(), "BatchGetSecretValue", map[string]any{"Filters": []map[string]any{{"Key": "name", "Values": strings.Fields(strings.Repeat("a ", 11))}}}, "ValidationException", "")
}

func TestBatchGetSecretValueAccess(t *testing.T) {
	d := testDeps()
	d.Config.Server.AccessMode = "owner"
	owner, other, root := uint32(1000), uint32(1001), uint32(0)
	for name, uid := range map[string]*uint32{"owned": &owner, "other": &other, "unowned": nil} {
		uid := uid
		seedMetadata(t, d, name, func(s *model.Secret) {
			value := name
			s.OwnerUID = uid
			s.Versions = []*model.Version{{VersionID: token1, SecretString: &value, Stages: []string{model.StageCurrent}, CreatedDate: d.Now()}}
		})
	}
	denied := map[string]any{"ErrorCode": "AccessDeniedException", "Message": "User is not authorized to perform: secretsmanager:GetSecretValue on this resource because no identity-based policy allows the action"}
	assertBatchAccess := func(t *testing.T, uid *uint32, wantValues []string, wantDenied []string) {
		t.Helper()
		status, body := callAsUID(t, d, uid, "BatchGetSecretValue", map[string]any{"SecretIdList": []string{"owned", "other", "unowned"}})
		if status != 200 {
			t.Fatalf("batch: %d %s", status, body)
		}
		var out map[string]any
		if err := json.Unmarshal(body, &out); err != nil {
			t.Fatal(err)
		}
		var values []string
		for _, entry := range out["SecretValues"].([]any) {
			values = append(values, entry.(map[string]any)["Name"].(string))
		}
		if !reflect.DeepEqual(values, wantValues) {
			t.Fatalf("values %v, want %v", values, wantValues)
		}
		var deniedIDs []string
		if errs, ok := out["Errors"].([]any); ok {
			for _, entry := range errs {
				e := entry.(map[string]any)
				want := map[string]any{"SecretId": e["SecretId"], "ErrorCode": denied["ErrorCode"], "Message": denied["Message"]}
				if !reflect.DeepEqual(e, want) {
					t.Fatalf("error entry %#v, want %#v", e, want)
				}
				deniedIDs = append(deniedIDs, e["SecretId"].(string))
			}
		}
		if !reflect.DeepEqual(deniedIDs, wantDenied) {
			t.Fatalf("denied %v, want %v", deniedIDs, wantDenied)
		}
	}
	assertBatchAccess(t, &owner, []string{"owned"}, []string{"other", "unowned"})
	assertBatchAccess(t, &other, []string{"other"}, []string{"owned", "unowned"})
	assertBatchAccess(t, &root, []string{"owned", "other", "unowned"}, nil)
	assertBatchAccess(t, nil, nil, []string{"owned", "other", "unowned"})
	// Filters only list secrets the caller can access, and never report errors.
	for _, tc := range []struct {
		name string
		uid  *uint32
		want []string
	}{
		{"owner", &owner, []string{"owned"}},
		{"other", &other, []string{"other"}},
		{"root", &root, []string{"other", "owned", "unowned"}},
		{"unknown", nil, nil},
	} {
		t.Run("filters/"+tc.name, func(t *testing.T) {
			status, body := callAsUID(t, d, tc.uid, "BatchGetSecretValue", map[string]any{"Filters": []map[string]any{}})
			if status != 200 {
				t.Fatalf("batch: %d %s", status, body)
			}
			var out map[string]any
			if err := json.Unmarshal(body, &out); err != nil {
				t.Fatal(err)
			}
			var names []string
			for _, entry := range out["SecretValues"].([]any) {
				names = append(names, entry.(map[string]any)["Name"].(string))
			}
			if !reflect.DeepEqual(names, tc.want) || out["Errors"] != nil {
				t.Fatalf("names %v errors %v, want %v", names, out["Errors"], tc.want)
			}
		})
	}
	// A paging token is bound to the caller too.
	status, body := callAsUID(t, d, &root, "BatchGetSecretValue", map[string]any{"Filters": []map[string]any{}, "MaxResults": 1})
	if status != 200 {
		t.Fatalf("first page: %d %s", status, body)
	}
	var first map[string]any
	if err := json.Unmarshal(body, &first); err != nil {
		t.Fatal(err)
	}
	status, body = callAsUID(t, d, &owner, "BatchGetSecretValue", map[string]any{"Filters": []map[string]any{}, "NextToken": first["NextToken"]})
	if status != 400 || api.ErrorType(body) != "InvalidNextTokenException" {
		t.Fatalf("cross-caller token: %d %s", status, body)
	}
}

func TestBatchGetSecretValueAccessDay(t *testing.T) {
	d := testDeps()
	create(t, d, "secret")
	counter := &countingStore{Store: d.Store}
	d.Store = counter
	callOK(t, d, region, "BatchGetSecretValue", `{"SecretIdList":["secret"]}`)
	callOK(t, d, region, "BatchGetSecretValue", `{"SecretIdList":["secret"]}`)
	if counter.updates != 1 {
		t.Fatalf("same-day reads made %d writes, want 1", counter.updates)
	}
	d.Clock.(*sm.FakeClock).Advance(24 * time.Hour)
	callOK(t, d, region, "BatchGetSecretValue", `{"SecretIdList":["secret"]}`)
	if counter.updates != 2 || !stored(t, d, "secret").LastAccessedDate.Equal(model.Day(d.Now())) {
		t.Fatal("next-day read did not update access date once")
	}
}
