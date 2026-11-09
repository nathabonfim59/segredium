// This separate module keeps the AWS SDK out of the server's dependencies.
package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	if err := run(ctx); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	for _, region := range []string{"us-east-1", "us-west-2"} {
		cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
		if err != nil {
			return err
		}
		client := secretsmanager.NewFromConfig(cfg)
		for _, binary := range []bool{false, true} {
			if err := exercise(ctx, client, region, binary); err != nil {
				return fmt.Errorf("%s binary=%t: %w", region, binary, err)
			}
		}
		if err := listChecks(ctx, client); err != nil {
			return fmt.Errorf("%s list: %w", region, err)
		}
		if err := batchChecks(ctx, client); err != nil {
			return fmt.Errorf("%s batch: %w", region, err)
		}
		for _, binary := range []bool{false, true} {
			if err := mutationChecks(ctx, client, binary); err != nil {
				return fmt.Errorf("%s lifecycle binary=%t: %w", region, binary, err)
			}
		}
		_, err = client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{SecretId: aws.String("e2e/go/absent")})
		var missing *types.ResourceNotFoundException
		if !errors.As(err, &missing) {
			return fmt.Errorf("missing secret error: %w", err)
		}
		_, err = client.DescribeSecret(ctx, &secretsmanager.DescribeSecretInput{SecretId: aws.String("e2e/go/absent")})
		if !errors.As(err, &missing) {
			return fmt.Errorf("missing describe error: %w", err)
		}
		fmt.Printf("PASS: aws-sdk-go-v2 %s: string, binary, stages, idempotency, describe, list, batch, pagination, update, delete, restore, typed errors\n", region)
	}
	return nil
}

func batchChecks(ctx context.Context, client *secretsmanager.Client) error {
	names := []string{"e2e/go/binary-false", "e2e/go/binary-true"}
	expected := make(map[string]*secretsmanager.GetSecretValueOutput, len(names))
	for _, name := range names {
		value, err := client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{SecretId: aws.String(name)})
		if err != nil {
			return err
		}
		expected[name] = value
	}
	ids := append(slices.Clone(names), names[0], "e2e/go/absent")
	batch, err := client.BatchGetSecretValue(ctx, &secretsmanager.BatchGetSecretValueInput{SecretIdList: ids})
	if err != nil {
		return err
	}
	if batch.NextToken != nil || len(batch.SecretValues) != 3 || len(batch.Errors) != 1 {
		return fmt.Errorf("unexpected batch by id: %+v", batch)
	}
	missing := batch.Errors[0]
	if aws.ToString(missing.SecretId) != "e2e/go/absent" || aws.ToString(missing.ErrorCode) != "ResourceNotFoundException" || aws.ToString(missing.Message) == "" {
		return fmt.Errorf("unexpected batch error: %+v", missing)
	}
	seen := map[string]int{}
	for _, entry := range batch.SecretValues {
		name := aws.ToString(entry.Name)
		seen[name]++
		reference := expected[name]
		if reference == nil || aws.ToString(entry.ARN) != aws.ToString(reference.ARN) ||
			aws.ToString(entry.VersionId) != aws.ToString(reference.VersionId) ||
			!slices.Equal(entry.VersionStages, []string{"AWSCURRENT"}) ||
			entry.CreatedDate == nil || reference.CreatedDate == nil || !entry.CreatedDate.Equal(*reference.CreatedDate) ||
			!bytes.Equal(entry.SecretBinary, reference.SecretBinary) || aws.ToString(entry.SecretString) != aws.ToString(reference.SecretString) {
			return fmt.Errorf("unexpected batch value: %+v", entry)
		}
	}
	if seen[names[0]] != 2 || seen[names[1]] != 1 {
		return fmt.Errorf("unexpected duplicate batch entries: %+v", seen)
	}
	// A deleted secret is a per-secret error, not a failed call.
	scheduled := "e2e/go/batch-scheduled"
	created, err := client.CreateSecret(ctx, &secretsmanager.CreateSecretInput{Name: aws.String(scheduled), SecretString: aws.String("scheduled")})
	if err != nil {
		return err
	}
	if _, err := client.DeleteSecret(ctx, &secretsmanager.DeleteSecretInput{SecretId: created.ARN, RecoveryWindowInDays: aws.Int64(7)}); err != nil {
		return err
	}
	batch, err = client.BatchGetSecretValue(ctx, &secretsmanager.BatchGetSecretValueInput{SecretIdList: []string{scheduled}})
	if err != nil || len(batch.SecretValues) != 0 || batch.NextToken != nil || len(batch.Errors) != 1 {
		return fmt.Errorf("unexpected batch for deleted secret: %+v, error: %v", batch, err)
	}
	deleted := batch.Errors[0]
	if aws.ToString(deleted.SecretId) != scheduled || aws.ToString(deleted.ErrorCode) != "InvalidRequestException" {
		return fmt.Errorf("unexpected batch deleted error: %+v", deleted)
	}
	if _, err := client.DeleteSecret(ctx, &secretsmanager.DeleteSecretInput{SecretId: created.ARN, ForceDeleteWithoutRecovery: aws.Bool(true)}); err != nil {
		return err
	}
	filters := []types.Filter{{Key: "name", Values: []string{"e2e/go/binary-"}}}
	first, err := client.BatchGetSecretValue(ctx, &secretsmanager.BatchGetSecretValueInput{Filters: filters, MaxResults: aws.Int32(1)})
	if err != nil || len(first.SecretValues) != 1 || first.NextToken == nil {
		return fmt.Errorf("unexpected first batch page: %+v, error: %v", first, err)
	}
	last, err := client.BatchGetSecretValue(ctx, &secretsmanager.BatchGetSecretValueInput{Filters: filters, MaxResults: aws.Int32(20), NextToken: first.NextToken})
	if err != nil || len(last.SecretValues) != 1 || last.NextToken != nil {
		return fmt.Errorf("unexpected last batch page: %+v, error: %v", last, err)
	}
	paged := []string{aws.ToString(first.SecretValues[0].Name), aws.ToString(last.SecretValues[0].Name)}
	slices.Sort(paged)
	if !slices.Equal(paged, names) {
		return fmt.Errorf("unexpected batch pages: %+v", paged)
	}
	empty, err := client.BatchGetSecretValue(ctx, &secretsmanager.BatchGetSecretValueInput{Filters: []types.Filter{{Key: "name", Values: []string{"e2e/go/absent"}}}})
	if err != nil || len(empty.SecretValues) != 0 || empty.NextToken != nil {
		return fmt.Errorf("unexpected empty batch: %+v, error: %v", empty, err)
	}
	_, err = client.BatchGetSecretValue(ctx, &secretsmanager.BatchGetSecretValueInput{Filters: filters, NextToken: aws.String("invalid-token")})
	var invalidToken *types.InvalidNextTokenException
	if !errors.As(err, &invalidToken) {
		return fmt.Errorf("invalid batch token error: %w", err)
	}
	_, err = client.BatchGetSecretValue(ctx, &secretsmanager.BatchGetSecretValueInput{})
	var parameter *types.InvalidParameterException
	if !errors.As(err, &parameter) {
		return fmt.Errorf("batch without ids or filters: %w", err)
	}
	_, err = client.BatchGetSecretValue(ctx, &secretsmanager.BatchGetSecretValueInput{SecretIdList: names, Filters: filters})
	if !errors.As(err, &parameter) {
		return fmt.Errorf("batch with ids and filters: %w", err)
	}
	_, err = client.BatchGetSecretValue(ctx, &secretsmanager.BatchGetSecretValueInput{SecretIdList: names, MaxResults: aws.Int32(1)})
	if !errors.As(err, &parameter) {
		return fmt.Errorf("batch ids with MaxResults: %w", err)
	}
	_, err = client.BatchGetSecretValue(ctx, &secretsmanager.BatchGetSecretValueInput{SecretIdList: names, NextToken: aws.String("token")})
	if !errors.As(err, &parameter) {
		return fmt.Errorf("batch ids with NextToken: %w", err)
	}
	return nil
}

func mutationChecks(ctx context.Context, client *secretsmanager.Client, binary bool) error {
	name := aws.String(fmt.Sprintf("e2e/go/lifecycle-%t", binary))
	created, err := client.CreateSecret(ctx, &secretsmanager.CreateSecretInput{Name: name, SecretString: aws.String("original")})
	if err != nil {
		return err
	}
	metadata, err := client.UpdateSecret(ctx, &secretsmanager.UpdateSecretInput{SecretId: created.ARN, Description: aws.String("updated metadata")})
	if err != nil || metadata.VersionId != nil || aws.ToString(metadata.ARN) != aws.ToString(created.ARN) || aws.ToString(metadata.Name) != *name {
		return fmt.Errorf("metadata-only update: %+v, error: %v", metadata, err)
	}
	described, err := client.DescribeSecret(ctx, &secretsmanager.DescribeSecretInput{SecretId: name})
	if err != nil || aws.ToString(described.Description) != "updated metadata" || len(described.VersionIdsToStages) != 1 {
		return fmt.Errorf("metadata-only describe: %+v, error: %v", described, err)
	}
	input := &secretsmanager.UpdateSecretInput{SecretId: created.ARN}
	if binary {
		input.SecretBinary = []byte{0, 255, 127, 2}
	} else {
		input.SecretString = aws.String("updated string")
	}
	// The SDK generates ClientRequestToken on this value-bearing update.
	updated, err := client.UpdateSecret(ctx, input)
	if err != nil || len(aws.ToString(updated.VersionId)) < 32 || aws.ToString(updated.VersionId) == aws.ToString(created.VersionId) {
		return fmt.Errorf("value update: %+v, error: %v", updated, err)
	}
	input.ClientRequestToken = updated.VersionId
	repeated, err := client.UpdateSecret(ctx, input)
	if err != nil || aws.ToString(repeated.VersionId) != aws.ToString(updated.VersionId) {
		return fmt.Errorf("update idempotency: %+v, error: %v", repeated, err)
	}
	got, err := client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{SecretId: created.ARN})
	if err != nil || aws.ToString(got.VersionId) != aws.ToString(updated.VersionId) || !bytes.Equal(got.SecretBinary, input.SecretBinary) || aws.ToString(got.SecretString) != aws.ToString(input.SecretString) || !slices.Equal(got.VersionStages, []string{"AWSCURRENT"}) {
		return fmt.Errorf("updated value: %+v, error: %v", got, err)
	}
	previous, err := client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{SecretId: name, VersionStage: aws.String("AWSPREVIOUS")})
	if err != nil || aws.ToString(previous.VersionId) != aws.ToString(created.VersionId) || aws.ToString(previous.SecretString) != "original" {
		return fmt.Errorf("update previous: %+v, error: %v", previous, err)
	}
	if binary {
		input.SecretBinary = []byte("conflict")
	} else {
		input.SecretString = aws.String("conflict")
	}
	_, err = client.UpdateSecret(ctx, input)
	var conflict *types.ResourceExistsException
	if !errors.As(err, &conflict) {
		return fmt.Errorf("update conflict: %v", err)
	}
	_, err = client.DeleteSecret(ctx, &secretsmanager.DeleteSecretInput{SecretId: name, RecoveryWindowInDays: aws.Int64(6)})
	var parameter *types.InvalidParameterException
	if !errors.As(err, &parameter) {
		return fmt.Errorf("delete window validation: %v", err)
	}
	before := time.Now()
	deleted, err := client.DeleteSecret(ctx, &secretsmanager.DeleteSecretInput{SecretId: created.ARN, RecoveryWindowInDays: aws.Int64(7)})
	if err != nil || deleted.DeletionDate == nil || deleted.DeletionDate.Before(before.Add(7*24*time.Hour-time.Second)) || deleted.DeletionDate.After(time.Now().Add(7*24*time.Hour+time.Second)) || aws.ToString(deleted.ARN) != aws.ToString(created.ARN) || aws.ToString(deleted.Name) != *name {
		return fmt.Errorf("scheduled delete: %+v, error: %v", deleted, err)
	}
	_, err = client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{SecretId: name})
	var invalid *types.InvalidRequestException
	if !errors.As(err, &invalid) {
		return fmt.Errorf("scheduled value error: %v", err)
	}
	_, err = client.UpdateSecret(ctx, &secretsmanager.UpdateSecretInput{SecretId: name, Description: aws.String("blocked")})
	if !errors.As(err, &invalid) {
		return fmt.Errorf("scheduled update error: %v", err)
	}
	_, err = client.DeleteSecret(ctx, &secretsmanager.DeleteSecretInput{SecretId: name})
	if !errors.As(err, &invalid) {
		return fmt.Errorf("scheduled repeat delete error: %v", err)
	}
	_, err = client.CreateSecret(ctx, &secretsmanager.CreateSecretInput{Name: name})
	if !errors.As(err, &invalid) {
		return fmt.Errorf("scheduled name reservation error: %v", err)
	}
	for _, include := range []bool{false, true} {
		listed, err := client.ListSecrets(ctx, &secretsmanager.ListSecretsInput{IncludePlannedDeletion: aws.Bool(include), Filters: []types.Filter{{Key: "name", Values: []string{*name}}}})
		if err != nil {
			return err
		}
		want := 0
		if include {
			want = 1
		}
		if len(listed.SecretList) != want {
			return fmt.Errorf("planned deletion include=%t: %+v", include, listed)
		}
	}
	for range 2 {
		restored, err := client.RestoreSecret(ctx, &secretsmanager.RestoreSecretInput{SecretId: created.ARN})
		if err != nil || aws.ToString(restored.ARN) != aws.ToString(created.ARN) || aws.ToString(restored.Name) != *name {
			return fmt.Errorf("restore: %+v, error: %v", restored, err)
		}
	}
	recovered, err := client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{SecretId: name})
	if err != nil || aws.ToString(recovered.VersionId) != aws.ToString(got.VersionId) || !bytes.Equal(recovered.SecretBinary, got.SecretBinary) || aws.ToString(recovered.SecretString) != aws.ToString(got.SecretString) {
		return fmt.Errorf("restored value: %+v, error: %v", recovered, err)
	}
	defaultStart := time.Now()
	deleted, err = client.DeleteSecret(ctx, &secretsmanager.DeleteSecretInput{SecretId: name})
	if err != nil || deleted.DeletionDate == nil || deleted.DeletionDate.Before(defaultStart.Add(30*24*time.Hour-time.Second)) || deleted.DeletionDate.After(time.Now().Add(30*24*time.Hour+time.Second)) {
		return fmt.Errorf("default recovery window: %+v, error: %v", deleted, err)
	}
	forced, err := client.DeleteSecret(ctx, &secretsmanager.DeleteSecretInput{SecretId: name, ForceDeleteWithoutRecovery: aws.Bool(true)})
	if err != nil || forced.DeletionDate == nil || aws.ToString(forced.ARN) != aws.ToString(created.ARN) {
		return fmt.Errorf("force delete scheduled secret: %+v, error: %v", forced, err)
	}
	_, err = client.RestoreSecret(ctx, &secretsmanager.RestoreSecretInput{SecretId: name})
	var missing *types.ResourceNotFoundException
	if !errors.As(err, &missing) {
		return fmt.Errorf("force-deleted restore: %v", err)
	}
	_, err = client.DeleteSecret(ctx, &secretsmanager.DeleteSecretInput{SecretId: name, ForceDeleteWithoutRecovery: aws.Bool(true)})
	if err != nil {
		return fmt.Errorf("force delete nonexistent secret: %w", err)
	}
	recreated, err := client.CreateSecret(ctx, &secretsmanager.CreateSecretInput{Name: name})
	if err != nil || aws.ToString(recreated.ARN) == aws.ToString(created.ARN) {
		return fmt.Errorf("reuse force-deleted name: %+v, error: %v", recreated, err)
	}
	_, err = client.DeleteSecret(ctx, &secretsmanager.DeleteSecretInput{SecretId: recreated.ARN, ForceDeleteWithoutRecovery: aws.Bool(true)})
	return err
}

func exercise(ctx context.Context, client *secretsmanager.Client, region string, binary bool) error {
	name := fmt.Sprintf("e2e/go/binary-%t", binary)
	input := &secretsmanager.CreateSecretInput{
		Name: aws.String(name), Description: aws.String("E2E metadata"),
		Tags: []types.Tag{{Key: aws.String("Environment"), Value: aws.String("E2E")}},
	}
	if binary {
		input.SecretBinary = []byte{0, 255, 128, 1}
	} else {
		input.SecretString = aws.String("first string")
	}
	// Omitting ClientRequestToken exercises the SDK's automatic token generation.
	first, err := client.CreateSecret(ctx, input)
	if err != nil {
		return err
	}
	if aws.ToString(first.Name) != name || len(aws.ToString(first.VersionId)) < 32 ||
		!strings.Contains(aws.ToString(first.ARN), ":secretsmanager:"+region+":") {
		return fmt.Errorf("unexpected create output: %+v", first)
	}
	input.ClientRequestToken = first.VersionId
	repeated, err := client.CreateSecret(ctx, input)
	if err != nil || aws.ToString(repeated.VersionId) != aws.ToString(first.VersionId) {
		return fmt.Errorf("create idempotency: %v", err)
	}
	put := &secretsmanager.PutSecretValueInput{SecretId: first.ARN, ClientRequestToken: aws.String(strings.Repeat("p", 32)), VersionStages: []string{"AWSPENDING"}}
	if binary {
		put.SecretBinary = []byte{255, 0, 129, 2}
	} else {
		put.SecretString = aws.String("second string")
	}
	pending, err := client.PutSecretValue(ctx, put)
	if err != nil || !slices.Equal(pending.VersionStages, []string{"AWSPENDING"}) {
		return fmt.Errorf("pending version: %v", err)
	}
	current, err := client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{SecretId: first.ARN})
	if err != nil || aws.ToString(current.VersionId) != aws.ToString(first.VersionId) {
		return fmt.Errorf("AWSPENDING changed AWSCURRENT: %v", err)
	}
	put.ClientRequestToken = aws.String(strings.Repeat("c", 32))
	put.VersionStages = nil
	second, err := client.PutSecretValue(ctx, put)
	if err != nil {
		return err
	}
	if !slices.Equal(second.VersionStages, []string{"AWSCURRENT"}) {
		return fmt.Errorf("current stages: %v", second.VersionStages)
	}
	retry, err := client.PutSecretValue(ctx, put)
	if err != nil || aws.ToString(retry.VersionId) != aws.ToString(second.VersionId) {
		return fmt.Errorf("put idempotency: %v", err)
	}
	got, err := client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{SecretId: first.ARN})
	if err != nil {
		return err
	}
	if aws.ToString(got.VersionId) != aws.ToString(second.VersionId) || got.CreatedDate == nil ||
		!slices.Equal(got.VersionStages, []string{"AWSCURRENT"}) ||
		!bytes.Equal(got.SecretBinary, put.SecretBinary) || aws.ToString(got.SecretString) != aws.ToString(put.SecretString) {
		return fmt.Errorf("unexpected get output: %+v", got)
	}
	previous, err := client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{SecretId: first.ARN, VersionStage: aws.String("AWSPREVIOUS")})
	if err != nil || aws.ToString(previous.VersionId) != aws.ToString(first.VersionId) ||
		!bytes.Equal(previous.SecretBinary, input.SecretBinary) || aws.ToString(previous.SecretString) != aws.ToString(input.SecretString) {
		return fmt.Errorf("previous version: %v", err)
	}
	described, err := client.DescribeSecret(ctx, &secretsmanager.DescribeSecretInput{SecretId: first.ARN})
	if err != nil {
		return err
	}
	if aws.ToString(described.ARN) != aws.ToString(first.ARN) || aws.ToString(described.Name) != name ||
		aws.ToString(described.Description) != "E2E metadata" || described.CreatedDate == nil ||
		described.LastAccessedDate == nil || !described.LastAccessedDate.Equal(described.LastAccessedDate.UTC().Truncate(24*time.Hour)) ||
		described.KmsKeyId != nil || described.RotationEnabled != nil || described.DeletedDate != nil ||
		len(described.Tags) != 1 || aws.ToString(described.Tags[0].Key) != "Environment" || aws.ToString(described.Tags[0].Value) != "E2E" ||
		len(described.VersionIdsToStages) != 3 ||
		!slices.Equal(described.VersionIdsToStages[aws.ToString(first.VersionId)], []string{"AWSPREVIOUS"}) ||
		!slices.Equal(described.VersionIdsToStages[aws.ToString(pending.VersionId)], []string{"AWSPENDING"}) ||
		!slices.Equal(described.VersionIdsToStages[aws.ToString(second.VersionId)], []string{"AWSCURRENT"}) {
		return fmt.Errorf("unexpected describe output: %+v", described)
	}
	listed, err := client.ListSecrets(ctx, &secretsmanager.ListSecretsInput{Filters: []types.Filter{
		{Key: "name", Values: []string{name}}, {Key: "tag-key", Values: []string{"Environ"}}, {Key: "tag-value", Values: []string{"E2"}},
	}})
	if err != nil {
		return err
	}
	if len(listed.SecretList) != 1 || aws.ToString(listed.SecretList[0].ARN) != aws.ToString(first.ARN) ||
		len(listed.SecretList[0].SecretVersionsToStages) != 3 ||
		!slices.Equal(listed.SecretList[0].SecretVersionsToStages[aws.ToString(second.VersionId)], []string{"AWSCURRENT"}) {
		return fmt.Errorf("unexpected filtered list: %+v", listed)
	}
	if binary {
		put.SecretBinary = []byte("conflicting value")
	} else {
		put.SecretString = aws.String("conflicting value")
	}
	_, err = client.PutSecretValue(ctx, put)
	var exists *types.ResourceExistsException
	if !errors.As(err, &exists) {
		return fmt.Errorf("token conflict error: %w", err)
	}
	return nil
}

func listChecks(ctx context.Context, client *secretsmanager.Client) error {
	input := &secretsmanager.ListSecretsInput{
		Filters:    []types.Filter{{Key: "name", Values: []string{"e2e/go/binary-"}}},
		MaxResults: aws.Int32(1), SortBy: "name", SortOrder: "desc",
	}
	first, err := client.ListSecrets(ctx, input)
	if err != nil {
		return err
	}
	if len(first.SecretList) != 1 || aws.ToString(first.SecretList[0].Name) != "e2e/go/binary-true" || first.NextToken == nil {
		return fmt.Errorf("unexpected first list page: %+v", first)
	}
	input.NextToken, input.MaxResults = first.NextToken, aws.Int32(100)
	last, err := client.ListSecrets(ctx, input)
	if err != nil {
		return err
	}
	if len(last.SecretList) != 1 || aws.ToString(last.SecretList[0].Name) != "e2e/go/binary-false" || last.NextToken != nil {
		return fmt.Errorf("unexpected last list page: %+v", last)
	}
	empty, err := client.ListSecrets(ctx, &secretsmanager.ListSecretsInput{Filters: []types.Filter{{Key: "name", Values: []string{"e2e/go/absent"}}}})
	if err != nil || len(empty.SecretList) != 0 || empty.NextToken != nil {
		return fmt.Errorf("unexpected empty list: %+v, error: %v", empty, err)
	}
	_, err = client.ListSecrets(ctx, &secretsmanager.ListSecretsInput{NextToken: aws.String("invalid-token")})
	var invalid *types.InvalidNextTokenException
	if !errors.As(err, &invalid) {
		return fmt.Errorf("invalid list token error: %w", err)
	}
	return nil
}
