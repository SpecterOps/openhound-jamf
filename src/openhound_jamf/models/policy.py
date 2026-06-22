from dataclasses import dataclass

from openhound.core.asset import BaseAsset
from pydantic import BaseModel, Field

from openhound_jamf.graph import JAMFNodeProperties
from openhound_jamf.main import app


class BasePolicy(BaseModel):
    id: int
    name: str | None = None


class IdName(BaseModel):
    id: int | None = None
    name: str | None = None


class DateTimeLimitations(BaseModel):
    activation_date: str | None = None
    activation_date_epoch: int | None = None
    activation_date_utc: str | None = None
    expiration_date: str | None = None
    expiration_date_epoch: int | None = None
    expiration_date_utc: str | None = None
    no_execute_start: str | None = None
    no_execute_end: str | None = None


class NetworkLimitations(BaseModel):
    minimum_network_connection: str | None = None
    any_ip_address: bool | None = None
    network_segments: list[dict[str, IdName]] = Field(default_factory=list)


class OverrideDefaultSettings(BaseModel):
    target_drive: str | None = None
    distribution_point: str | None = None
    force_afp_smb: bool | None = None
    sus: str | None = None


class Computer(BaseModel):
    id: int
    name: str | None = None
    udid: str


class LimitToUsers(BaseModel):
    user_groups: list[dict[str, str]] | list[str] = Field(default_factory=list)


class Limitations(BaseModel):
    users: list[dict[str, IdName]] = Field(default_factory=list)
    user_groups: list[dict[str, IdName]] = Field(default_factory=list)
    network_segments: list[dict[str, IdName]] = Field(default_factory=list)
    ibeacons: list[dict[str, IdName]] = Field(default_factory=list)


class Exclusions(BaseModel):
    computers: list[Computer]
    computer_groups: list[dict[str, IdName]] = Field(default_factory=list)
    buildings: list[dict[str, IdName]] = Field(default_factory=list)
    departments: list[dict[str, IdName]] = Field(default_factory=list)
    users: list[dict[str, IdName]] = Field(default_factory=list)
    user_groups: list[dict[str, IdName]] = Field(default_factory=list)
    network_segments: list[dict[str, IdName]] = Field(default_factory=list)
    ibeacons: list[dict[str, IdName]] = Field(default_factory=list)


class Scope(BaseModel):
    all_computers: bool
    computers: list[Computer]
    computer_groups: list[dict[str, IdName]] = Field(default_factory=list)
    buildings: list[dict[str, IdName]] = Field(default_factory=list)
    departments: list[dict[str, IdName]] = Field(default_factory=list)
    limit_to_users: LimitToUsers | None = None
    limitations: Limitations | None = None
    exclusions: Exclusions


class Category(BaseModel):
    id: int | None = None
    name: str | None = None
    display_in: bool | None = None
    feature_in: bool | None = None


class SelfServiceIcon(BaseModel):
    id: int | None = None
    filename: str | None = None
    uri: str | None = None


class SelfService(BaseModel):
    use_for_self_service: bool | None = None
    self_service_display_name: str | None = None
    install_button_text: str | None = None
    reinstall_button_text: str | None = None
    self_service_description: str | None = None
    force_users_to_view_description: bool | None = None
    self_service_icon: SelfServiceIcon = Field(default_factory=dict)
    feature_on_main_page: bool | None = None
    self_service_categories: list[Category] = Field(default_factory=list)


class Package(BaseModel):
    id: int | None = None
    name: str | None = None


class Packages(BaseModel):
    size: int | None = None
    package: Package | None = None


class PackageConfiguration(BaseModel):
    packages: list[Packages] = Field(default_factory=list)
    distribution_point: str | None = None


class Script(BaseModel):
    id: int | None = None
    name: str | None = None
    priority: str | None = None
    parameter4: str | None = None
    parameter5: str | None = None
    parameter6: str | None = None
    parameter7: str | None = None
    parameter8: str | None = None
    parameter9: str | None = None
    parameter10: str | None = None
    parameter11: str | None = None


class ManagementAccount(BaseModel):
    action: str | None = None


class OpenFirmwareEfiPassword(BaseModel):
    of_mode: str | None = None
    of_password_sha256: str | None = None


class DBinding(BaseModel):
    id: int | None = None
    name: str | None = None


class DBindings(BaseModel):
    size: int | None = None
    binding: DBinding | None = None


class MaintenanceAccount(BaseModel):
    action: str | None = None
    username: str | None = None
    admin: bool | None = None
    home: str | None = None


class MaintenanceAccounts(BaseModel):
    size: int | None = None
    account: MaintenanceAccount | None = None


class AccountMaintenance(BaseModel):
    accounts: list[MaintenanceAccounts] = Field(default_factory=list)
    directory_bindings: list[DBindings] = Field(default_factory=list)
    management_account: ManagementAccount | None = None
    open_firmware_efi_password: OpenFirmwareEfiPassword | None = None


class Reboot(BaseModel):
    message: str | None = None
    startup_disk: str | None = None
    specify_startup: str | None = None
    no_user_logged_in: str | None = None
    user_logged_in: str | None = None
    minutes_until_reboot: int | None = None
    start_reboot_timer_immediately: bool | None = None
    file_vault_2_reboot: bool | None = None


class Maintenance(BaseModel):
    recon: bool | None = None
    reset_name: bool | None = None
    install_all_cached_packages: bool | None = None
    heal: bool | None = None
    prebindings: bool | None = None
    permissions: bool | None = None
    byhost: bool | None = None
    system_cache: bool | None = None
    user_cache: bool | None = None
    verify: bool | None = None


class FilesProcesses(BaseModel):
    search_by_path: str | None = None
    delete_file: bool | None = None
    locate_file: str | None = None
    update_locate_database: bool | None = None
    spotlight_search: str | None = None
    search_for_process: str | None = None
    kill_process: bool | None = None
    run_command: str | None = None


class UserInteraction(BaseModel):
    message_start: str | None = None
    allow_users_to_defer: bool | None = None
    allow_deferral_until_utc: str | None = None
    allow_deferral_minutes: int | None = None
    message_finish: str | None = None


class DiskEncryption(BaseModel):
    action: str | None = None


class DockItem(BaseModel):
    id: int | None = None
    name: str | None = None
    action: str | None = None


class DockItems(BaseModel):
    size: int | None = None
    dock_item: DockItem | None = None


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
    trigger: str | None = None
    trigger_checkin: bool | None = None
    trigger_enrollment_complete: bool | None = None
    trigger_login: bool | None = None
    trigger_network_state_changed: bool | None = None
    trigger_startup: bool | None = None
    trigger_other: str | None = None
    frequency: str
    retry_event: str | None = None
    retry_attempts: int | None = None
    notify_on_each_failed_retry: bool | None = None
    location_user_only: bool | None = None
    target_drive: str | None = None
    offline: bool | None = None
    category: IdName | None = None
    date_time_limitations: DateTimeLimitations | None = None
    network_limitations: NetworkLimitations | None = None
    override_default_settings: OverrideDefaultSettings | None = None
    network_requirements: str | None = None
    site: IdName | None = None

    scope: Scope
    self_service: SelfService | None = None
    package_configuration: PackageConfiguration | None = None
    scripts: list[Script]
    printers: list | None = Field(default_factory=list)
    dock_items: list[DockItems] = Field(default_factory=list)
    account_maintenance: AccountMaintenance | None = None
    reboot: Reboot | None = None
    maintenance: Maintenance | None = None
    files_processes: FilesProcesses | None = None
    user_interaction: UserInteraction | None = None
    disk_encryption: DiskEncryption | None = None

    @property
    def as_node(self):
        return None

    @property
    def edges(self):
        return []
