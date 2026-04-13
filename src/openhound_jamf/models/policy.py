from dataclasses import dataclass
from enum import Enum
from typing import Any

from openhound.core.asset import BaseAsset
from pydantic import BaseModel

from openhound_jamf.graph import JAMFNodeProperties
from openhound_jamf.main import app


class Trigger(Enum):
    CHECKIN = "CHECKIN"
    LOGIN = "LOGIN"
    OTHER = "OTHER"
    STARTUP = "STARTUP"
    ENROLLMENT_COMPLETE = "ENROLLMENT_COMPLETE"
    NETWORK_STATE_CHANGED = "NETWORK_STATE_CHANGED"
    EVENT = "EVENT"


class Retry(Enum):
    none = "none"
    immediate = "immediate"
    interval = "interval"


class BasePolicy(BaseModel):
    id: int
    name: str


class IdName(BaseModel):
    id: int
    name: str


class DateTimeLimitations(BaseModel):
    activation_date: str
    activation_date_epoch: int
    activation_date_utc: str
    expiration_date: str
    expiration_date_epoch: int
    expiration_date_utc: str
    no_execute_on: dict[str, Any]
    no_execute_start: str
    no_execute_end: str


class NetworkLimitations(BaseModel):
    minimum_network_connection: str
    any_ip_address: bool
    network_segments: list[dict[str, Any]]


class OverrideDefaultSettings(BaseModel):
    target_drive: str
    distribution_point: str
    force_afp_smb: bool
    sus: str


class Computer(BaseModel):
    id: int
    name: str
    udid: str


class LimitToUsers(BaseModel):
    user_groups: list[dict[str, Any]]


class Limitations(BaseModel):
    users: list[dict[str, Any]]
    user_groups: list[dict[str, Any]]
    network_segments: list[dict[str, Any]]
    ibeacons: list[dict[str, Any]]


class Exclusions(BaseModel):
    computers: list[Computer]
    computer_groups: list[dict[str, Any]]
    buildings: list[dict[str, Any]]
    departments: list[dict[str, Any]]
    users: list[dict[str, Any]]
    user_groups: list[dict[str, Any]]
    network_segments: list[dict[str, Any]]
    ibeacons: list[dict[str, Any]]


class Scope(BaseModel):
    all_computers: bool
    computers: list[Computer]
    computer_groups: list[dict[str, Any]]
    buildings: list[dict[str, Any]]
    departments: list[dict[str, Any]]
    limit_to_users: LimitToUsers
    limitations: Limitations
    exclusions: Exclusions


class SelfService(BaseModel):
    use_for_self_service: bool
    self_service_display_name: str
    install_button_text: str
    reinstall_button_text: str
    self_service_description: str
    force_users_to_view_description: bool
    self_service_icon: dict[str, Any]
    feature_on_main_page: bool
    self_service_categories: list[dict[str, Any]]


class PackageConfiguration(BaseModel):
    packages: list[dict[str, Any]]
    distribution_point: str


class Script(BaseModel):
    id: int
    name: str
    priority: str
    parameter4: str
    parameter5: str
    parameter6: str
    parameter7: str
    parameter8: str
    parameter9: str
    parameter10: str
    parameter11: str


class ManagementAccount(BaseModel):
    action: str


class OpenFirmwareEfiPassword(BaseModel):
    of_mode: str
    of_password_sha256: str


class AccountMaintenance(BaseModel):
    accounts: list[dict[str, Any]]
    directory_bindings: list[dict[str, Any]]
    management_account: ManagementAccount
    open_firmware_efi_password: OpenFirmwareEfiPassword


class Reboot(BaseModel):
    message: str
    startup_disk: str
    specify_startup: str
    no_user_logged_in: str
    user_logged_in: str
    minutes_until_reboot: int
    start_reboot_timer_immediately: bool
    file_vault_2_reboot: bool


class Maintenance(BaseModel):
    recon: bool
    reset_name: bool
    install_all_cached_packages: bool
    heal: bool
    prebindings: bool
    permissions: bool
    byhost: bool
    system_cache: bool
    user_cache: bool
    verify: bool


class FilesProcesses(BaseModel):
    search_by_path: str
    delete_file: bool
    locate_file: str
    update_locate_database: bool
    spotlight_search: str
    search_for_process: str
    kill_process: bool
    run_command: str


class UserInteraction(BaseModel):
    message_start: str
    allow_users_to_defer: bool
    allow_deferral_until_utc: str
    allow_deferral_minutes: int
    message_finish: str


class DiskEncryption(BaseModel):
    action: str


@dataclass
class PolicyProperties(JAMFNodeProperties):
    """JAMF Policy node properties"""

    pass


@app.asset(
    description="Jamf Policy asset. Returns a node representing a Jamf Policy and edges to its tenant."
)
class Policy(BaseAsset):
    """JAMF policy resource parsed into a Pydantic model.

    Parses the raw JAMF policy payload and exposes OpenGraph Node and Edges via
    the `as_node` and `edges` properties.

    Args:
        BaseAsset (BaseAsset): Base class providing OpenGraph node/edge exports.
    """

    id: int
    name: str
    enabled: bool
    trigger: Trigger
    trigger_checkin: bool
    trigger_enrollment_complete: bool
    trigger_login: bool
    trigger_network_state_changed: bool
    trigger_startup: bool
    trigger_other: str
    frequency: str
    retry_event: Retry
    retry_attempts: int
    notify_on_each_failed_retry: bool
    location_user_only: bool
    target_drive: str
    offline: bool
    category: IdName
    date_time_limitations: DateTimeLimitations
    network_limitations: NetworkLimitations
    override_default_settings: OverrideDefaultSettings
    network_requirements: str
    site: IdName

    scope: Scope
    self_service: SelfService
    package_configuration: PackageConfiguration
    scripts: list[Script]
    printers: list[str]
    dock_items: list[dict[str, Any]]
    account_maintenance: AccountMaintenance
    reboot: Reboot
    maintenance: Maintenance
    files_processes: FilesProcesses
    user_interaction: UserInteraction
    disk_encryption: DiskEncryption

    @property
    def as_node(self):
        # TODO: Verify if we shouldnt create this node
        # properties = PolicyProperties(
        #     id=self.id,
        #     name=self.name,
        #     displayname=self.name,
        #     tier=1,
        #     tenant=self.tenant_id,
        # )
        # return JAMFNode(kinds=[nk.POLICY], properties=properties)
        return None

    # @property
    # def _tenant_id(self) -> str:
    #     return self._lookup.tenant_id()

    @property
    def edges(self):
        return []
