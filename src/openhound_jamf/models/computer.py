from dataclasses import dataclass
from datetime import datetime

from openhound.core.asset import EdgeDef, NodeDef
from openhound.core.models.entries_dataclass import Edge, EdgePath, EdgeProperties
from pydantic import BaseModel, ConfigDict, Field

from openhound_jamf.graph import JAMFAsset, JAMFNode, JAMFNodeProperties
from openhound_jamf.kinds import edges as ek
from openhound_jamf.kinds import nodes as nk
from openhound_jamf.main import app


@dataclass
class ComputerProperties(JAMFNodeProperties):
    """JAMF Computer node properties"""

    managed: bool
    supervised: bool
    enrolled_via_dep: bool
    user_approved_mdm: bool
    site_id: str
    site_name: str
    jamf_version: str
    ip_address: str
    last_reported_ip_v4: str
    last_reported_ip_v6: str
    udid: str
    computer_group_memberships: list[str]
    model: str | None = None
    mac_address: str | None = None
    make: str | None = None
    model_name: str | None = None
    model_identifier: str | None = None
    username: str | None = None
    realname: str | None = None
    email: str | None = None
    email_address: str | None = None
    phone_number: str | None = None
    position: str | None = None
    realname: str | None = None
    os_name: str | None = None
    os_version: str | None = None
    os_build: str | None = None
    processor_type: str | None = None
    recovery_lock_enabled: bool | None = None
    institutional_recovery_key: bool | None = None
    serial_number: str | None = None
    sip_status: str | None = None
    xprotect_version: str | None = None
    active_directory_status: str | None = None
    firewall_enabled: bool | None = None
    gatekeeper_status: str | None = None
    is_apple_silicon: bool | None = None


class RemoteManagement(BaseModel):
    managed: bool
    management_username: str | None = Field(default=None, alias="managementUsername")


class UserManagementInfo(BaseModel):
    capable_user: str = Field(alias="capableUser")
    management_id: str = Field(alias="managementId")


class MdmCapable(BaseModel):
    capable: bool
    # capable_users: list[str] = Field(alias="capableUsers") deprecated
    user_management_info: list[UserManagementInfo] = Field(alias="userManagementInfo")


class Site(BaseModel):
    id: str
    name: str


class EnrollmentMethod(BaseModel):
    id: str
    object_name: str | None = Field(alias="objectName", default=None)
    object_type: str = Field(alias="objectType")


class UserAndLocation(BaseModel):
    username: str | None = None
    realname: str | None = None
    email: str | None = None
    position: str | None = None
    phone: str | None = None


class Hardware(BaseModel):
    model: str
    make: str
    model_identifier: str = Field(alias="modelIdentifier")
    mac_address: str = Field(alias="macAddress")
    serial_number: str | None = Field(default=None, alias="serialNumber")
    processor_type: str | None = Field(default=None, alias="processorType")
    apple_silicon: bool | None = Field(default=None, alias="appleSilicon")


class Security(BaseModel):
    sip_status: str | None = Field(default=None, alias="sipStatus")
    gatekeeper_status: str | None = Field(default=None, alias="gatekeeperStatus")
    xprotect_version: str | None = Field(default=None, alias="xprotectVersion")
    recovery_lock_enabled: bool | None = Field(
        default=None, alias="recoveryLockEnabled"
    )
    firewall_enabled: bool | None = Field(default=None, alias="firewallEnabled")


class OperatingSystem(BaseModel):
    name: str | None = None
    version: str | None = None
    build: str | None = None
    active_directory_status: str | None = Field(
        default=None, alias="activeDirectoryStatus"
    )


class DiskEncryption(BaseModel):
    institutional_recovery_key_present: bool | None = Field(
        default=None, alias="institutionalRecoveryKeyPresent"
    )


class GroupMembership(BaseModel):
    group_id: str = Field(alias="groupId")
    group_name: str = Field(alias="groupName")


@app.asset(
    node=NodeDef(
        kind=nk.COMPUTER,
        description="Jamf Computer node",
        icon="laptop",
        properties=ComputerProperties,
    ),
    edges=[
        # EdgeDef(
        #     start=nk.COMPUTER,
        #     end=nk.USER,
        #     kind=ek.ASSIGNED_USER,
        #     description="The specified user is assigned to the source computer",
        #     traversable=True,
        # ),
        EdgeDef(
            start=nk.TENANT,
            end=nk.COMPUTER,
            kind=ek.CONTAINS,
            description="Something something",
        ),
    ],
)
class Computer(JAMFAsset):
    """JAMF computer resource parsed into a Pydantic model.

    Parses the raw JAMF computer payload and exposes OpenGraph Node and Edges via
    the `as_node` and `edges` properties.

    Args:
        BaseAsset (BaseAsset): Base class providing OpenGraph node/edge exports.

    Returns:
        Node (ComputerNode): OpenGraph node representation of Computer
    """

    model_config = ConfigDict(populate_by_name=True)

    id: str
    udid: str
    extension_attributes: list = Field(alias="extensionAttributes")
    name: str
    last_ip_address: str = Field(alias="lastIpAddress")
    last_reported_ip_v4: str = Field(alias="lastReportedIpV4")
    last_reported_ip_v6: str = Field(alias="lastReportedIpV6")
    jamf_binary_version: str = Field(alias="jamfBinaryVersion")
    platform: str
    barcode1: str | None = None
    barcode2: str | None = None
    asset_tag: str | None = Field(default=None, alias="assetTag")
    remote_management: RemoteManagement = Field(alias="remoteManagement")
    supervised: bool
    mdm_capable: MdmCapable = Field(alias="mdmCapable")
    report_date: str = Field(alias="reportDate")
    last_contact_time: str = Field(alias="lastContactTime")
    last_cloud_backup_date: str | None = Field(
        default=None, alias="lastCloudBackupDate"
    )
    last_enrolled_date: str = Field(alias="lastEnrolledDate")
    mdm_profile_expiration: datetime | None = Field(
        default=None, alias="mdmProfileExpiration"
    )
    initial_entry_date: str = Field(alias="initialEntryDate")
    distribution_point: str | None = Field(default=None, alias="distributionPoint")
    itunes_store_account_active: bool = Field(alias="itunesStoreAccountActive")
    enrolled_via_automated_device_enrollment: bool = Field(
        alias="enrolledViaAutomatedDeviceEnrollment"
    )
    user_approved_mdm: bool = Field(alias="userApprovedMdm")
    enrollment_method: EnrollmentMethod | None = Field(
        default=None, alias="enrollmentMethod"
    )
    declarative_device_management_enabled: bool = Field(
        alias="declarativeDeviceManagementEnabled"
    )
    management_id: str = Field(alias="managementId")
    last_logged_in_username_self_service: str | None = Field(
        default=None, alias="lastLoggedInUsernameSelfService"
    )
    last_logged_in_username_self_service_timestamp: str | None = Field(
        default=None, alias="lastLoggedInUsernameSelfServiceTimestamp"
    )
    last_logged_in_username_binary: str | None = Field(
        default=None, alias="lastLoggedInUsernameBinary"
    )
    last_logged_in_username_binary_timestamp: str | None = Field(
        default=None, alias="lastLoggedInUsernameBinaryTimestamp"
    )
    # last_reported_ip: str = Field(alias="lastReportedIp")
    site: Site
    user_and_location: UserAndLocation | None = Field(
        default=None, alias="userAndLocation"
    )
    hardware: Hardware | None = None
    security: Security | None = None
    operating_system: OperatingSystem | None = Field(
        default=None, alias="operatingSystem"
    )
    disk_encryption: DiskEncryption | None = Field(default=None, alias="diskEncryption")
    group_memberships: list[GroupMembership] = Field(
        default_factory=list, alias="groupMemberships"
    )

    @property
    def as_node(self):
        properties = ComputerProperties(
            name=self.name,
            displayname=self.name,
            id=self.id,
            tenant=self.tenant_id,
            tier=1,
            managed=self.remote_management.managed,
            jamf_version=self.jamf_binary_version,
            supervised=self.supervised,
            enrolled_via_dep=self.enrolled_via_automated_device_enrollment,
            user_approved_mdm=self.user_approved_mdm,
            site_id=self.site.id,
            site_name=self.site.name,
            udid=self.udid,
            computer_group_memberships=[g.group_name for g in self.group_memberships],
            ip_address=self.last_ip_address,
            last_reported_ip_v4=self.last_reported_ip_v4,
            last_reported_ip_v6=self.last_reported_ip_v6,
            environmentid=self.tenant_node_id,
        )

        if self.user_and_location:
            properties.username = self.user_and_location.username
            properties.email_address = self.user_and_location.email
            properties.phone_number = self.user_and_location.phone
            properties.position = self.user_and_location.position
            properties.realname = self.user_and_location.realname

        if self.operating_system:
            properties.os_name = self.operating_system.name
            properties.os_version = self.operating_system.version
            properties.os_build = self.operating_system.build
            properties.active_directory_status = (
                self.operating_system.active_directory_status
            )

        if self.security:
            properties.recovery_lock_enabled = self.security.recovery_lock_enabled
            properties.xprotect_version = self.security.xprotect_version
            properties.firewall_enabled = self.security.firewall_enabled
            properties.gatekeeper_status = self.security.gatekeeper_status
            properties.sip_status = self.security.sip_status

        if self.disk_encryption:
            properties.institutional_recovery_key = (
                self.disk_encryption.institutional_recovery_key_present
            )

        if self.hardware:
            properties.processor_type = self.hardware.processor_type
            properties.serial_number = self.hardware.serial_number
            properties.is_apple_silicon = self.hardware.apple_silicon

        return JAMFNode(kinds=[nk.COMPUTER], properties=properties)

    @property
    def _node_id(self) -> str:
        return self.as_node.id

    @property
    def _contains_tenant_edge(self):
        if self.site.id == "-1":
            yield Edge(
                kind=ek.CONTAINS,
                start=EdgePath(match_by="id", value=self.tenant_node_id),
                end=EdgePath(match_by="id", value=self._node_id),
                properties=EdgeProperties(traversable=True),
            )

    @property
    def _contains_site_edge(self):
        if self.site.id != "-1":
            site_node_id = JAMFNode.guid(self.site.id, nk.SITE, self.tenant_id)
            yield Edge(
                kind=ek.CONTAINS,
                start=EdgePath(match_by="id", value=site_node_id),
                end=EdgePath(match_by="id", value=self._node_id),
                properties=EdgeProperties(traversable=True),
            )

    @property
    def edges(self):
        yield from self._contains_tenant_edge
        yield from self._contains_site_edge
