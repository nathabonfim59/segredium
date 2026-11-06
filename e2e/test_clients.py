"""Check e2e pagination against old and current client models without AWS dependencies."""
import pathlib
import runpy
import types
import unittest
from unittest.mock import patch


def load_clients():
    exceptions = types.ModuleType("botocore.exceptions")
    exceptions.ClientError = type("ClientError", (Exception,), {})
    with patch.dict("sys.modules", {
        "boto3": types.ModuleType("boto3"),
        "botocore": types.ModuleType("botocore"),
        "botocore.exceptions": exceptions,
    }):
        return runpy.run_path(str(pathlib.Path(__file__).with_name("clients.py")))


class PaginationChecks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.clients = load_clients()

    def check_client(self, kind, supports_sort_by):
        wrapper = self.clients[kind]
        client = wrapper.__new__(wrapper)
        members = {"SortOrder": object()}
        if supports_sort_by:
            members["SortBy"] = object()

        def operation_model(operation):
            self.assertEqual(operation, "ListSecrets")
            return types.SimpleNamespace(input_shape=types.SimpleNamespace(members=members))

        client.client = types.SimpleNamespace(meta=types.SimpleNamespace(
            service_model=types.SimpleNamespace(operation_model=operation_model)))
        prefix = f"e2e/{client.label.replace(' ', '-')}/Secret"
        calls = []

        def call(operation, *, error=None, **params):
            self.assertEqual(operation, "list_secrets")
            calls.append(params)
            if "SortBy" in params and not supports_sort_by:
                raise ValueError("Unknown parameter in input: SortBy")
            if error:
                self.assertEqual(error, "InvalidNextTokenException")
                self.assertEqual(params, {"NextToken": "invalid-token"})
                return
            if params["Filters"][0]["Values"] == ["e2e/absent"]:
                return {"SecretList": []}
            self.assertEqual(params["SortOrder"], "desc")
            # exercise() creates String first, Binary second. CreatedDate desc
            # reverses that order; sorting by name desc preserves it.
            names = [prefix + "String", prefix + "Binary"]
            if "SortBy" not in params:
                names.reverse()
            if "NextToken" in params:
                self.assertEqual(params["NextToken"], "page-2")
                self.assertEqual(params["MaxResults"], 100)
                return {"SecretList": [{"Name": names[1]}]}
            self.assertEqual(params["MaxResults"], 1)
            return {"SecretList": [{"Name": names[0]}], "NextToken": "page-2"}

        client.call = call
        self.clients["pagination_checks"](client)
        self.assertEqual(len(calls), 4)
        for params in calls[:2]:
            self.assertEqual("SortBy" in params, supports_sort_by)
            if supports_sort_by:
                self.assertEqual(params["SortBy"], "name")

    def test_old_boto_model_uses_created_date(self):
        self.check_client("Boto", supports_sort_by=False)

    def test_current_boto_model_uses_name(self):
        self.check_client("Boto", supports_sort_by=True)

    def test_cli_uses_name(self):
        self.check_client("CLI", supports_sort_by=True)


if __name__ == "__main__":
    unittest.main()
