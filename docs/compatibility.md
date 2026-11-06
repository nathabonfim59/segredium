# API compatibility

segredium implements the AWS JSON 1.1 protocol:

- requests are `POST /` with `X-Amz-Target: secretsmanager.<Operation>`;
- member names and shapes follow botocore's `secretsmanager/2017-10-17/service-2.json`;
- timestamps are epoch seconds;
- unset optional members are omitted;
- errors are `{"__type", "Message"}` plus `x-amzn-ErrorType`, using AWS's exception names and,
  where AWS documents one, its message text.

Clients built from the AWS service model (all AWS SDKs, AWS CLI, Terraform's AWS provider and
the like) therefore need no changes. AWS documentation, not other emulators, is the reference
for behavior.

`segredium operations` prints the operations the running build implements.

## Implemented

| Operation | Notes |
|---|---|
| `CreateSecret` | String or binary value, or no value. Description, `KmsKeyId` (recorded, not used for encryption), tags, `Type`. `ClientRequestToken` idempotency: a retry with the same value succeeds, a different value is `ResourceExistsException`. |
| `GetSecretValue` | By name, full ARN or partial ARN. Selects by `VersionId` and/or `VersionStage` (default `AWSCURRENT`). A deleted secret is `InvalidRequestException`. |
| `PutSecretValue` | New version with `AWSCURRENT` (the previous current version becomes `AWSPREVIOUS`) or custom `VersionStages`. Token idempotency. Old unlabeled versions are pruned as in AWS (at most 100, after 24 h). |
| `DescribeSecret` | Full metadata, `VersionIdsToStages`, tags, dates. Works on secrets scheduled for deletion. |
| `ListSecrets` | `Filters` (`name`, `description`, `tag-key`, `tag-value`, `primary-region`, `owning-service`, `all`; prefix match, `!` negation, AWS case rules), `SortOrder`, `SortBy`, `IncludePlannedDeletion`, `MaxResults` (1–100), opaque `NextToken`. Values are never loaded to list. |
| `UpdateSecret` | Metadata-only updates create no version. With a value, it acts like `PutSecretValue` for `AWSCURRENT`. Changing `KmsKeyId` keeps labeled versions' key history. |
| `DeleteSecret` | `RecoveryWindowInDays` 7–30 (default 30): the name stays reserved and the secret is readable only through `DescribeSecret`/`ListSecrets`. `ForceDeleteWithoutRecovery` removes it immediately and frees the name. Force-deleting a nonexistent secret succeeds, as in AWS. |
| `RestoreSecret` | Cancels a scheduled deletion. A no-op on a secret that isn't scheduled. Refused once the window has passed. |

Expired recovery windows are purged by one background timer that wakes at the next deadline, or
after `storage.purge_interval` (default 1 h), whichever comes first.

Not yet:

- **Signature verification:** any credentials are accepted, and the region is read from the
  SigV4 scope.
- **KMS:** `KmsKeyId` is stored and reported, but every value is encrypted with the local
  master key.
- **Replication:** `AddReplicaRegions` is not acted upon yet.
- **Rotation:** `RotationEnabled` and rotation rules are not used yet.

## Not implemented yet

These return `UnknownOperationException`:

- `BatchGetSecretValue`
- `ListSecretVersionIds`
- `UpdateSecretVersionStage`
- `GetRandomPassword`
- `TagResource`, `UntagResource`
- `RotateSecret`, `CancelRotateSecret`
- `ReplicateSecretToRegions`, `RemoveRegionsFromReplication`, `StopReplicationToReplica`
- `PutResourcePolicy`, `GetResourcePolicy`, `DeleteResourcePolicy`, `ValidateResourcePolicy`

## Tested clients

Each change is checked end to end on a clean Linux VM through `/etc/hosts` and the trusted CA, with
no endpoint override, in `us-east-1` and `us-west-2`:

- AWS CLI v2;
- boto3, including the older 1.34 series shipped by Ubuntu;
- aws-sdk-go-v2.
