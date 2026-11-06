"""Exercise stock CLI v2 and boto3 through /etc/hosts with certificate verification."""
import base64
import datetime
import json
import subprocess
import uuid

import boto3
from botocore.exceptions import ClientError


class CLI:
    label = "AWS CLI v2"

    def __init__(self, region):
        self.region = region

    def call(self, operation, *, error=None, **params):
        encoded = {
            key: base64.b64encode(value).decode() if isinstance(value, bytes) else value
            for key, value in params.items()
        }
        result = subprocess.run(
            ["aws", "--region", self.region, "--output", "json", "--cli-binary-format", "base64", "--no-paginate",
             "secretsmanager", operation.replace("_", "-"), "--cli-input-json", json.dumps(encoded)],
            text=True, capture_output=True, timeout=30,
        )
        if error:
            assert result.returncode != 0, result.stdout
            assert f"({error})" in result.stderr, result.stderr
            return
        assert result.returncode == 0, result.stderr
        output = json.loads(result.stdout)
        if "SecretBinary" in output:
            output["SecretBinary"] = base64.b64decode(output["SecretBinary"])
        # CLI v2 renders modeled timestamps as ISO8601, including nested list entries.
        normalize_dates(output)
        return output


class Boto:
    label = "boto3"

    def __init__(self, region):
        self.region = region
        self.client = boto3.client("secretsmanager", region_name=region)
        assert self.client.meta.endpoint_url == f"https://secretsmanager.{region}.amazonaws.com"

    def call(self, operation, *, error=None, **params):
        try:
            output = getattr(self.client, operation)(**params)
        except ClientError as exc:
            assert error is not None, exc
            assert exc.response["Error"]["Code"] == error, exc
            assert exc.response["ResponseMetadata"]["HTTPStatusCode"] == 400, exc
            return
        assert error is None, output
        return output


def token():
    return str(uuid.uuid4())


def normalize_dates(value):
    if isinstance(value, dict):
        for key, item in value.items():
            if key.endswith("Date") and isinstance(item, str):
                value[key] = datetime.datetime.fromisoformat(item)
            else:
                normalize_dates(item)
    elif isinstance(value, list):
        for item in value:
            normalize_dates(item)


def metadata_checks(client, first, first_token, pending_token, next_token):
    described = client.call("describe_secret", SecretId=first["ARN"])
    assert described["ARN"] == first["ARN"] and described["Name"] == first["Name"], described
    assert described["Description"] == "E2E metadata", described
    assert described["Tags"] == [{"Key": "Environment", "Value": "E2E"}], described
    stages = {first_token: ["AWSPREVIOUS"], pending_token: ["AWSPENDING"], next_token: ["AWSCURRENT"]}
    assert described["VersionIdsToStages"] == stages, described
    assert isinstance(described["CreatedDate"], datetime.datetime), described
    accessed = described["LastAccessedDate"]
    assert isinstance(accessed, datetime.datetime) and accessed.utcoffset() == datetime.timedelta(0), described
    assert (accessed.hour, accessed.minute, accessed.second, accessed.microsecond) == (0, 0, 0, 0), described
    for member in ["SecretString", "SecretBinary", "OwnerUID", "KmsKeyId", "RotationEnabled", "DeletedDate"]:
        assert member not in described, described
    listed = client.call("list_secrets", Filters=[
        {"Key": "name", "Values": [first["Name"]]},
        {"Key": "tag-key", "Values": ["Environ"]},
        {"Key": "tag-value", "Values": ["E2"]},
    ])
    assert len(listed["SecretList"]) == 1, listed
    entry = listed["SecretList"][0]
    assert entry["ARN"] == first["ARN"] and entry["SecretVersionsToStages"] == stages, listed
    assert entry["LastAccessedDate"] == described["LastAccessedDate"], listed
    for member in ["SecretString", "SecretBinary", "OwnerUID", "VersionIdsToStages", "ReplicationStatus"]:
        assert member not in entry, listed


def pagination_checks(client):
    prefix = f"e2e/{client.label.replace(' ', '-')}/Secret"
    filters = [{"Key": "name", "Values": [prefix]}]
    sort = {"SortOrder": "desc", "SortBy": "name"}
    expected = [prefix + "String", prefix + "Binary"]
    if isinstance(client, Boto):
        members = client.client.meta.service_model.operation_model("ListSecrets").input_shape.members
        if "SortBy" not in members:
            # Older botocore models only support CreatedDate sorting. exercise()
            # creates Binary after String, so descending creation order reverses them.
            del sort["SortBy"]
            expected.reverse()
    first = client.call("list_secrets", Filters=filters, MaxResults=1, **sort)
    assert [s["Name"] for s in first["SecretList"]] == expected[:1], first
    assert first.get("NextToken"), first
    last = client.call("list_secrets", Filters=filters, MaxResults=100,
                       NextToken=first["NextToken"], **sort)
    assert [s["Name"] for s in last["SecretList"]] == expected[1:], last
    assert "NextToken" not in last, last
    empty = client.call("list_secrets", Filters=[{"Key": "name", "Values": ["e2e/absent"]}])
    assert empty["SecretList"] == [] and "NextToken" not in empty, empty
    client.call("list_secrets", NextToken="invalid-token", error="InvalidNextTokenException")


def update_checks(client, first, member, previous_value, new_value, previous_token):
    before = client.call("describe_secret", SecretId=first["ARN"])
    metadata = client.call("update_secret", SecretId=first["ARN"], Description="updated metadata",
                           KmsKeyId="alias/e2e-update")
    assert set(metadata) - {"ResponseMetadata"} == {"ARN", "Name"}, metadata
    assert metadata["ARN"] == first["ARN"] and metadata["Name"] == first["Name"], metadata
    described = client.call("describe_secret", SecretId=first["ARN"])
    assert described["Description"] == "updated metadata", described
    assert described["KmsKeyId"] == "alias/e2e-update", described
    assert described["VersionIdsToStages"] == before["VersionIdsToStages"], described
    assert described["LastChangedDate"] >= before["LastChangedDate"], described

    version = token()
    params = dict(SecretId=first["Name"], ClientRequestToken=version, **{member: new_value})
    updated = client.call("update_secret", **params)
    assert set(updated) - {"ResponseMetadata"} == {"ARN", "Name", "VersionId"}, updated
    assert updated["VersionId"] == version and updated["ARN"] == first["ARN"], updated
    repeated = client.call("update_secret", **params)
    assert repeated["VersionId"] == version, repeated
    client.call("update_secret", SecretId=first["Name"], ClientRequestToken=version,
                **{member: previous_value}, error="ResourceExistsException")
    current = client.call("get_secret_value", SecretId=first["ARN"])
    assert current[member] == new_value and current["VersionId"] == version, current
    assert current["VersionStages"] == ["AWSCURRENT"], current
    other_member = "SecretBinary" if member == "SecretString" else "SecretString"
    assert other_member not in current, current
    previous = client.call("get_secret_value", SecretId=first["Name"], VersionStage="AWSPREVIOUS")
    assert previous[member] == previous_value and previous["VersionId"] == previous_token, previous
    client.call("update_secret", SecretId=first["Name"], Description="", KmsKeyId="")
    described = client.call("describe_secret", SecretId=first["ARN"])
    assert described.get("Description", "") == "" and "KmsKeyId" not in described, described
    assert described["VersionIdsToStages"][version] == ["AWSCURRENT"], described


def delete_restore_checks(client):
    name = f"e2e/{client.label.replace(' ', '-')}/delete-restore"
    created = client.call("create_secret", Name=name, SecretString="recoverable")
    # Exercise both the default window and the minimum explicit window.
    for days, params in [(30, {}), (7, {"RecoveryWindowInDays": 7})]:
        before = datetime.datetime.now(datetime.timezone.utc)
        deleted = client.call("delete_secret", SecretId=created["ARN"], **params)
        after = datetime.datetime.now(datetime.timezone.utc)
        assert set(deleted) - {"ResponseMetadata"} == {"ARN", "Name", "DeletionDate"}, deleted
        assert deleted["ARN"] == created["ARN"] and deleted["Name"] == name, deleted
        assert before + datetime.timedelta(days=days, seconds=-1) <= deleted["DeletionDate"] <= after + datetime.timedelta(days=days, seconds=1), deleted
        described = client.call("describe_secret", SecretId=name)
        assert isinstance(described["DeletedDate"], datetime.datetime), described
        client.call("get_secret_value", SecretId=name, error="InvalidRequestException")
        client.call("update_secret", SecretId=name, Description="blocked", error="InvalidRequestException")
        client.call("put_secret_value", SecretId=name, SecretString="blocked", error="InvalidRequestException")
        client.call("create_secret", Name=name, SecretString="reserved", error="InvalidRequestException")
        client.call("delete_secret", SecretId=name, RecoveryWindowInDays=7, error="InvalidRequestException")
        filters = [{"Key": "name", "Values": [name]}]
        assert client.call("list_secrets", Filters=filters)["SecretList"] == []
        entries = client.call("list_secrets", Filters=filters, IncludePlannedDeletion=True)["SecretList"]
        assert len(entries) == 1 and entries[0]["ARN"] == created["ARN"], entries
        restored = client.call("restore_secret", SecretId=name)
        assert set(restored) - {"ResponseMetadata"} == {"ARN", "Name"}, restored
        assert restored["ARN"] == created["ARN"] and restored["Name"] == name, restored
        assert "DeletedDate" not in client.call("describe_secret", SecretId=name)
        current = client.call("get_secret_value", SecretId=name)
        assert current["SecretString"] == "recoverable" and current["VersionId"] == created["VersionId"], current
        # Restoring an active secret is a successful no-op.
        assert client.call("restore_secret", SecretId=name)["ARN"] == created["ARN"]

    client.call("delete_secret", SecretId=name, RecoveryWindowInDays=7,
                ForceDeleteWithoutRecovery=True, error="InvalidParameterException")
    assert client.call("get_secret_value", SecretId=name)["SecretString"] == "recoverable"
    # Force deletion also overrides an existing recovery window.
    client.call("delete_secret", SecretId=name, RecoveryWindowInDays=7)
    forced = client.call("delete_secret", SecretId=name, ForceDeleteWithoutRecovery=True)
    assert forced["ARN"] == created["ARN"] and isinstance(forced["DeletionDate"], datetime.datetime), forced
    for operation in ["get_secret_value", "describe_secret", "restore_secret"]:
        client.call(operation, SecretId=name, error="ResourceNotFoundException")
    recreated = client.call("create_secret", Name=name, SecretString="new secret")
    assert recreated["ARN"] != created["ARN"], recreated
    client.call("delete_secret", SecretId=recreated["ARN"], ForceDeleteWithoutRecovery=True)


def exercise(client):
    for member, initial, updated in [
        ("SecretString", "first string", "second string"),
        ("SecretBinary", b"\x00\xfffirst\x80", b"\xff\x00second\x81"),
    ]:
        name = f"e2e/{client.label.replace(' ', '-')}/{member}"
        first_token = token()
        create = dict(Name=name, ClientRequestToken=first_token, Description="E2E metadata",
                      Tags=[{"Key": "Environment", "Value": "E2E"}], **{member: initial})
        first = client.call("create_secret", **create)
        assert first["Name"] == name and first["VersionId"] == first_token, first
        assert f":secretsmanager:{client.region}:" in first["ARN"], first
        repeated = client.call("create_secret", **create)
        assert repeated["ARN"] == first["ARN"] and repeated["VersionId"] == first_token, repeated
        client.call("create_secret", Name=name, **{member: initial}, error="ResourceExistsException")

        pending_token = token()
        pending = client.call("put_secret_value", SecretId=first["ARN"], ClientRequestToken=pending_token,
                              VersionStages=["AWSPENDING"], **{member: updated})
        assert pending["VersionId"] == pending_token and pending["VersionStages"] == ["AWSPENDING"], pending
        current = client.call("get_secret_value", SecretId=name)
        assert current[member] == initial and current["VersionId"] == first_token, current
        pending = client.call("get_secret_value", SecretId=name, VersionStage="AWSPENDING")
        assert pending[member] == updated and pending["VersionId"] == pending_token, pending

        next_token = token()
        put = dict(SecretId=name, ClientRequestToken=next_token, **{member: updated})
        second = client.call("put_secret_value", **put)
        assert second["VersionId"] == next_token and second["VersionStages"] == ["AWSCURRENT"], second
        repeated = client.call("put_secret_value", **put)
        assert repeated["VersionId"] == next_token, repeated
        client.call("put_secret_value", SecretId=name, ClientRequestToken=next_token,
                    **{member: initial}, error="ResourceExistsException")
        current = client.call("get_secret_value", SecretId=first["ARN"])
        assert current[member] == updated and current["VersionId"] == next_token, current
        assert current["VersionStages"] == ["AWSCURRENT"], current
        assert isinstance(current["CreatedDate"], (int, float, datetime.datetime)), current
        other_member = "SecretBinary" if member == "SecretString" else "SecretString"
        assert other_member not in current, current
        previous = client.call("get_secret_value", SecretId=name, VersionStage="AWSPREVIOUS")
        assert previous[member] == initial and previous["VersionId"] == first_token, previous
        metadata_checks(client, first, first_token, pending_token, next_token)

    pagination_checks(client)
    # Run after metadata/pagination assertions, which expect the original stage map.
    for member, previous, updated in [
        ("SecretString", "second string", "updated string"),
        ("SecretBinary", b"\xff\x00second\x81", b"\x80\xffupdated\x00"),
    ]:
        name = f"e2e/{client.label.replace(' ', '-')}/{member}"
        current = client.call("get_secret_value", SecretId=name)
        update_checks(client, current, member, previous, updated, current["VersionId"])
    delete_restore_checks(client)
    client.call("get_secret_value", SecretId="e2e/absent", error="ResourceNotFoundException")
    client.call("describe_secret", SecretId="e2e/absent", error="ResourceNotFoundException")
    print(f"PASS: {client.label} {client.region}: string, binary, stages, idempotency, describe, list, pagination, update, delete, restore, errors", flush=True)


if __name__ == "__main__":
    version = subprocess.check_output(["aws", "--version"], text=True)
    assert version.startswith("aws-cli/2."), version
    for kind in [CLI, Boto]:
        east = kind("us-east-1")
        west = kind("us-west-2")
        marker = f"e2e/{kind.label.replace(' ', '-')}/east-only"
        east.call("create_secret", Name=marker, SecretString="east only")
        west.call("get_secret_value", SecretId=marker, error="ResourceNotFoundException")
        west.call("describe_secret", SecretId=marker, error="ResourceNotFoundException")
        assert west.call("list_secrets", Filters=[{"Key": "name", "Values": [marker]}])["SecretList"] == []
        exercise(east)
        exercise(west)
