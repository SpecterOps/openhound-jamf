from functools import lru_cache

from duckdb import DuckDBPyConnection
from openhound.core.lookup import LookupManager


class JamfLookup(LookupManager):
    def __init__(self, client: DuckDBPyConnection, schema: str = "jamf"):
        super().__init__(client, schema)
        self.schema = schema
        self.client = client

    @lru_cache
    def sites(self):
        return self._find_all_objects(f"""SELECT id FROM {self.schema}.sites""")

    @lru_cache
    def tenant_id(self):
        return self._find_single_object(f"SELECT id FROM {self.schema}.tenant")

    @lru_cache
    def client_has_permission(self, client_id: int, privilege: str):
        return self._find_single_object(
            f"""
            SELECT role_name FROM {self.schema}.api_client_resolved_privileges
            WHERE client_id = ? AND privilege = ?
            """,
            [client_id, privilege],
        )

    @lru_cache
    def client_permissions(self, client_id: int):
        return self._find_single_object(
            f"""
            SELECT role_name FROM {self.schema}.api_client_resolved_privileges
            WHERE client_id = ?
        """,
            [client_id],
        )

    @lru_cache
    def all_computers(self):
        return self._find_all_objects(f"SELECT id FROM {self.schema}.computers")

    @lru_cache
    def computers_by_site(self, site_id: str):
        return self._find_all_objects(
            f"SELECT id FROM {self.schema}.computers WHERE site->>'$.id' = ?",
            [site_id],
        )

    @lru_cache
    def all_accounts(self):
        return self._find_all_objects(f"SELECT id FROM {self.schema}.account_details")

    @lru_cache
    def all_groups(self):
        return self._find_all_objects(
            f"SELECT id FROM {self.schema}.account_group_details"
        )

    @lru_cache
    def policies_exist(self):
        return self._find_single_object(
            f"SELECT id FROM {self.schema}.policy_details LIMIT 1"
        )

    @lru_cache
    def roles_exist(self):
        return self._find_single_object(
            f"SELECT id FROM {self.schema}.api_roles LIMIT 1"
        )

    @lru_cache
    def recurring_policy_computers(self):
        return self._find_all_objects(
            f"SELECT computer_id FROM {self.schema}.recurring_policy_target_computers"
        )

    @lru_cache
    def accounts_by_email(self, email: str):
        return self._find_all_objects(
            f"SELECT id FROM {self.schema}.account_details WHERE email = ?",
            [email],
        )

    @lru_cache
    def accounts_by_name(self, name: str):
        return self._find_all_objects(
            f"SELECT id FROM {self.schema}.account_details WHERE name = ? OR full_name = ?",
            [name, name],
        )

    @lru_cache
    def clients_exist(self):
        return self._find_single_object(
            f"SELECT id FROM {self.schema}.api_integrations LIMIT 1"
        )

    @lru_cache
    def extension_attrs_exist(self):
        return self._find_single_object(
            f"SELECT id FROM {self.schema}.computerextensionattributes LIMIT 1"
        )

    @lru_cache
    def sso_config_type(self):
        return self._find_single_object(
            f"SELECT configuration_type FROM {self.schema}.sso WHERE sso_enabled = true"
        )
