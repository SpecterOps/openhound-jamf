"""Fetch and parse the SAML metadata of a Jamf SSO configuration.

Jamf's SSO settings name the service provider (SP) and identity provider (IdP)
metadata only by URL. The SAML facts need the entity IDs and the assertion
consumer service (ACS) endpoints from that metadata, so the collector fetches it.
The fetch follows a strict origin policy because the URLs are tenant settings:
the SP metadata must come from the Jamf origin, and the IdP metadata from the
Jamf origin or an origin the operator listed.
"""

from typing import Any
from urllib.parse import urljoin, urlsplit
from xml.etree import ElementTree

from dlt.sources.helpers import requests
from pydantic import BaseModel, ConfigDict, Field

MAX_METADATA_BYTES = 2 * 1024 * 1024
MAX_REDIRECTS = 3
MAX_ACS_INDEX = 65535
REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
METADATA_NS = {"md": "urn:oasis:names:tc:SAML:2.0:metadata"}

ALLOWLIST_SETTING = "saml_metadata_allowed_origins"

# (scheme, host, port)
MetadataOrigin = tuple[str, str, int]


class AssertionConsumerService(BaseModel):
    """One ACS endpoint that the Jamf SP metadata lists."""

    model_config = ConfigDict(populate_by_name=True)

    acs_url: str = Field(alias="acsUrl")
    acs_binding: str | None = Field(alias="acsBinding", default=None)
    index: int | None = None
    is_default: bool = Field(alias="isDefault", default=False)


class ServiceProviderMetadata(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    entity_id: str | None = Field(alias="entityId", default=None)
    assertion_consumer_services: list[AssertionConsumerService] = Field(
        alias="assertionConsumerServices", default_factory=list
    )


class IdentityProviderMetadata(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    entity_id: str | None = Field(alias="entityId", default=None)


class SAMLMetadata(BaseModel):
    """The metadata that was fetched, and a secret-free error for each failed fetch."""

    sp: ServiceProviderMetadata | None = None
    idp: IdentityProviderMetadata | None = None
    errors: list[str] = Field(default_factory=list)


def _origin(url: str) -> MetadataOrigin | None:
    """Return the origin of a plain http(s) URL, or None for any other URL."""
    if any(char.isspace() or ord(char) < 32 or char == "\\" for char in url):
        return None
    try:
        parsed = urlsplit(url)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
        ):
            return None
        port = parsed.port
        if port is None:
            port = 443 if parsed.scheme == "https" else 80
    except ValueError:
        return None
    if port == 0:
        return None
    return parsed.scheme, parsed.hostname, port


def parse_allowed_origins(value: str | None) -> frozenset[MetadataOrigin]:
    """Parse a comma-separated list of HTTPS origins. Raise ValueError otherwise."""
    origins: set[MetadataOrigin] = set()
    for item in (value or "").split(","):
        candidate = item.strip()
        if not candidate:
            continue
        origin = _origin(candidate)
        try:
            parsed = urlsplit(candidate)
            is_bare = parsed.path in {"", "/"} and not parsed.query
        except ValueError:
            is_bare = False
        if origin is None or origin[0] != "https" or not is_bare:
            raise ValueError("SAML metadata allowlist entries must be HTTPS origins")
        origins.add(origin)
    return frozenset(origins)


def _resolve_url(base_url: str, value: str | None) -> str | None:
    """Return an absolute URL. A relative value is taken from the Jamf origin."""
    if not value or not value.strip():
        return None
    try:
        parsed = urlsplit(value)
    except ValueError:
        return value
    if parsed.scheme and parsed.netloc:
        return value
    base = urlsplit(base_url)
    path = value if value.startswith("/") else f"/{value}"
    return f"{base.scheme}://{base.netloc}{path}"


def _index(value: str | None) -> int | None:
    """Return an ACS `index` (xs:unsignedShort), None when absent.

    Raise `ElementTree.ParseError` for any other value. The length check comes
    before `int`, which rejects very long digit strings.
    """
    if value is None:
        return None
    if not (value.isascii() and value.isdigit() and len(value) <= 5):
        raise ElementTree.ParseError(f"invalid ACS index {value[:10]!r}")
    index = int(value)
    if index > MAX_ACS_INDEX:
        raise ElementTree.ParseError(f"invalid ACS index {value!r}")
    return index


class _NoDoctypeBuilder(ElementTree.TreeBuilder):
    """Tree builder that rejects a DOCTYPE, so no entity can be declared or expanded."""

    def doctype(self, name: str, pubid: str | None, system: str | None) -> None:
        raise ElementTree.ParseError("DOCTYPE is not allowed")


def is_absolute_uri(value: str) -> bool:
    """Return whether `value` has a scheme, so it is not a path relative to Jamf."""
    try:
        return bool(urlsplit(value).scheme)
    except ValueError:
        return False


def _parse(xml: bytes) -> tuple[str | None, list[AssertionConsumerService]]:
    """Return the entity ID and the SP ACS endpoints of one metadata document.

    Raise `ElementTree.ParseError` for malformed XML or any DOCTYPE. The check
    runs inside the parser, so it holds for every encoding of the body.
    """
    parser = ElementTree.XMLParser(target=_NoDoctypeBuilder())
    parser.feed(xml)
    root = parser.close()
    services = root.findall(
        "md:SPSSODescriptor/md:AssertionConsumerService", METADATA_NS
    )
    endpoints = [
        AssertionConsumerService(
            acsUrl=service.attrib["Location"],
            acsBinding=service.attrib.get("Binding"),
            index=_index(service.attrib.get("index")),
            isDefault=service.attrib.get("isDefault") == "true",
        )
        for service in services
        if service.attrib.get("Location")
    ]
    return root.attrib.get("entityID"), endpoints


def _fetch(
    url: str | None, allowed_origins: frozenset[MetadataOrigin]
) -> tuple[bytes | None, str | None]:
    """Return the metadata XML of `url`, or a secret-free error message.

    Every hop is checked before it is requested, because an access gateway can
    redirect a metadata request to another origin.
    """
    if not url:
        return None, "metadata URL is empty"
    current = url
    for redirects in range(MAX_REDIRECTS + 1):
        if _origin(current) not in allowed_origins:
            return None, (
                f"metadata URL is not allowed; permit its HTTPS origin with {ALLOWLIST_SETTING}"
                if redirects == 0
                else "metadata redirect is not allowed"
            )
        try:
            response = requests.get(
                current, timeout=(5, 30), stream=True, allow_redirects=False
            )
            try:
                if 300 <= response.status_code < 400:
                    location = response.headers.get("Location")
                    if response.status_code not in REDIRECT_STATUSES or not location:
                        return None, "metadata request failed"
                    if redirects == MAX_REDIRECTS:
                        return None, "metadata redirect limit exceeded"
                    current = urljoin(current, location)
                    continue
                response.raise_for_status()
                declared = response.headers.get("Content-Length", "")
                if declared.isdecimal() and int(declared) > MAX_METADATA_BYTES:
                    return None, "metadata exceeds size limit"
                body = bytearray()
                for chunk in response.iter_content(chunk_size=64 * 1024):
                    body.extend(chunk)
                    if len(body) > MAX_METADATA_BYTES:
                        return None, "metadata exceeds size limit"
                return bytes(body), None
            finally:
                response.close()
        except Exception:
            # A request error can carry a credential-bearing query, so the
            # message is fixed and never the exception text.
            return None, "metadata request failed"
    return None, "metadata redirect limit exceeded"


def _load(
    url: str | None, allowed_origins: frozenset[MetadataOrigin]
) -> tuple[tuple[str | None, list[AssertionConsumerService]] | None, str | None]:
    xml, error = _fetch(url, allowed_origins)
    if xml is None:
        return None, error
    try:
        return _parse(xml), None
    except ElementTree.ParseError:
        return None, "invalid metadata XML"


def enrich_sso_metadata(
    record: dict[str, Any],
    base_url: str,
    allowed_idp_origins: frozenset[MetadataOrigin],
) -> dict[str, Any]:
    """Return the SSO record with a `samlMetadata` entry for a SAML configuration."""
    settings = record.get("samlSettings") or {}
    if record.get("configurationType") != "SAML" or not settings:
        return record

    jamf_origin = _origin(base_url)
    jamf_origins = frozenset({jamf_origin}) if jamf_origin else frozenset()
    metadata = SAMLMetadata()

    sp, error = _load(_resolve_url(base_url, settings.get("entityId")), jamf_origins)
    if sp:
        entity_id, endpoints = sp
        if not entity_id:
            metadata.errors.append("sp: no entityID")
        metadata.sp = ServiceProviderMetadata(
            entityId=entity_id, assertionConsumerServices=endpoints
        )
    if error:
        metadata.errors.append(f"sp: {error}")

    idp, error = _load(
        _resolve_url(base_url, settings.get("idpUrl")),
        jamf_origins | allowed_idp_origins,
    )
    if idp:
        if not idp[0]:
            metadata.errors.append("idp: no entityID")
        metadata.idp = IdentityProviderMetadata(entityId=idp[0])
    if error:
        metadata.errors.append(f"idp: {error}")

    return {**record, "samlMetadata": metadata.model_dump(by_alias=True)}
