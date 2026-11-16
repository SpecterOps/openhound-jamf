"""Jamf SAML facts, built with the SAML producer library.

Jamf is a SAML service provider (SP). The SSO configuration names the identity
provider by metadata URL and maps assertions to Jamf accounts by email or by
username. Each asset here reads one SSO record and builds its SAML nodes and edges
only through `openhound_saml_producer`.
"""

import logging
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Literal

from openhound.core.models.entries_dataclass import Edge, EdgePath
from openhound_saml_producer import (
    NODE_DEFS,
    AccountFact,
    BuildWarning,
    IssuerFact,
    Producer,
    RouteFact,
    SamlNode,
    ServiceProviderFact,
    edge_defs,
    shared,
    sp,
)
from openhound_saml_producer.contract import (
    AccountField,
    AssertionField,
    ConditionTemplate,
    NodeKind,
)
from openhound_saml_producer.account_resolution import render_rule
from openhound_saml_producer.facts import (
    AccountFieldFact,
    AccountResolutionCondition,
    AccountResolutionRuleFact,
)
from pydantic import ConfigDict, Field

from openhound_jamf.graph import JAMFAsset, JAMFNode
from openhound_jamf.kinds import nodes as nk
from openhound_jamf.lookup import JamfAccountSAMLBinding
from openhound_jamf.main import app
from openhound_jamf.models.sso import SAMLSettings
from openhound_jamf.saml_metadata import AssertionConsumerService, SAMLMetadata

logger = logging.getLogger(__name__)

SAML = Producer(
    name="jamf_saml",
    extension="openhound-jamf",
    prefix="jamf_",
    technology="jamf",
    source_kind="SAML",
)

MappingAttribute = Literal["email", "name"]

# Jamf's `userMapping` setting, as the Jamf account attribute that it selects.
USER_MAPPING_ATTRIBUTES: dict[str, MappingAttribute] = {
    "EMAIL": "email",
    "USERNAME": "name",
}
USERNAME_FIELD = "username"


@dataclass(frozen=True)
class SAMLFacts:
    """The library facts of one Jamf SAML trust."""

    sp_entity_id: str
    provider: ServiceProviderFact
    issuer: IssuerFact
    routes: list[RouteFact]
    accounts: list[AccountFact]
    native: EdgePath


def _mapped_value(
    account: JamfAccountSAMLBinding, attribute: MappingAttribute
) -> str | None:
    """Return the source-exact account value that the user mapping reads."""
    value = account[attribute]
    return value if value and value.strip() else None


def _account_state(account: JamfAccountSAMLBinding) -> str:
    """Return the lifecycle state that Jamf names, or `unknown` for any other text."""
    state = (account["enabled"] or "").strip().lower()
    return state if state in {"enabled", "disabled"} else "unknown"


def _rule_for(attribute: MappingAttribute) -> AccountResolutionRuleFact:
    if attribute == "email":
        condition = AccountResolutionCondition(
            template=ConditionTemplate.COMMON_TO_COMMON,
            assertion_field=AssertionField.EMAIL,
            account_field=AccountField.EMAIL,
        )
    else:
        condition = AccountResolutionCondition(
            template=ConditionTemplate.COMMON_TO_ACCOUNT_FIELD,
            assertion_field=AssertionField.SCOPED_EXACT,
            account_name=USERNAME_FIELD,
        )
    return AccountResolutionRuleFact(
        conditions=[condition], name=f"Jamf {attribute} account resolution"
    )


class SAMLSSOBase(JAMFAsset):
    """An SSO record from which one SAML fact family is built."""

    model_config = ConfigDict(populate_by_name=True)

    configuration_type: str = Field(alias="configurationType")
    saml_settings: SAMLSettings | None = Field(alias="samlSettings", default=None)
    saml_metadata: SAMLMetadata | None = Field(alias="samlMetadata", default=None)
    sso_enabled: bool = Field(alias="ssoEnabled")

    @property
    def is_saml(self) -> bool:
        return self.configuration_type.upper() == "SAML" and bool(self.saml_settings)

    @property
    def _native_sso_id(self) -> str:
        return f"SSO-{self.configuration_type}"

    @property
    def _sp_entity_id(self) -> str | None:
        """Return the SP entity ID from metadata, else from the SSO settings."""
        if self.saml_metadata and self.saml_metadata.sp:
            if self.saml_metadata.sp.entity_id:
                return self.saml_metadata.sp.entity_id
        return self.saml_settings.entity_id if self.saml_settings else None

    @property
    def _issuer_entity_id(self) -> str | None:
        if self.saml_metadata and self.saml_metadata.idp:
            return self.saml_metadata.idp.entity_id
        return None

    @property
    def _mapping_attribute(self) -> MappingAttribute | None:
        settings = self.saml_settings
        if not settings or not settings.user_mapping:
            return None
        return USER_MAPPING_ATTRIBUTES.get(settings.user_mapping.upper())

    @property
    def _metadata_errors(self) -> list[str]:
        return self.saml_metadata.errors if self.saml_metadata else []

    def _routes(self, sp_entity_id: str) -> list[RouteFact]:
        sp_metadata = self.saml_metadata.sp if self.saml_metadata else None
        endpoints = sp_metadata.assertion_consumer_services if sp_metadata else []
        return [self._route(endpoint, sp_entity_id) for endpoint in endpoints]

    @staticmethod
    def _route(endpoint: AssertionConsumerService, sp_entity_id: str) -> RouteFact:
        return RouteFact(
            acs_url=endpoint.acs_url,
            sp_entity_id=sp_entity_id,
            binding=endpoint.acs_binding,
            is_default=endpoint.is_default,
            index=endpoint.index,
        )

    def _accounts(self, attribute: MappingAttribute) -> list[AccountFact]:
        """Return one fact for each account that has a value for the mapped attribute."""
        facts: list[AccountFact] = []
        for account in self._lookup.all_account_saml_bindings():
            value = _mapped_value(account, attribute)
            if value is None:
                continue
            is_email = attribute == "email"
            facts.append(
                AccountFact(
                    account=EdgePath(
                        match_by="id",
                        value=JAMFNode.guid(
                            str(account["id"]), nk.ACCOUNT, self.tenant_id
                        ),
                    ),
                    native_object_id=str(account["id"]),
                    native_object_name=account["name"],
                    match_values=[value],
                    email_match_values=[value] if is_email else [],
                    account_state=_account_state(account),
                    fields=[]
                    if is_email
                    else [
                        AccountFieldFact(
                            name=USERNAME_FIELD,
                            match_values=[value],
                            canonical_match_values=[value],
                        )
                    ],
                    extras={"jamf_mapping_attribute": attribute},
                )
            )
        return facts

    @property
    def facts(self) -> SAMLFacts | None:
        """Return the SAML facts, or None when the record has no usable SAML trust.

        The library builds the SP edges only for a trusted issuer, so a record
        whose IdP metadata was not observed has no facts.
        """
        sp_entity_id, issuer_entity_id = self._sp_entity_id, self._issuer_entity_id
        if not self.is_saml or not sp_entity_id or not issuer_entity_id:
            return None
        attribute = self._mapping_attribute
        accounts = self._accounts(attribute) if attribute else []
        # The library requires some account to give a field that a rule reads.
        rule = (
            _rule_for(attribute)
            if attribute and (attribute == "email" or accounts)
            else None
        )
        provider = ServiceProviderFact(
            environment_id=self.tenant_node_id,
            native_key=self._native_sso_id,
            native_kind=nk.SSO_INTEGRATION,
            native_object_id=self._native_sso_id,
            name=f"Jamf SAML SP {self.tenant_id}",
            enabled=self.sso_enabled,
            rules=[rule] if rule else [],
            extras={
                "jamf_entity_id": sp_entity_id,
                "jamf_metadata_errors": self._metadata_errors,
            },
        )
        return SAMLFacts(
            sp_entity_id=sp_entity_id,
            provider=provider,
            issuer=IssuerFact(entity_id=issuer_entity_id),
            routes=self._routes(sp_entity_id),
            accounts=accounts,
            native=EdgePath(
                match_by="id",
                value=JAMFNode.guid(
                    self._native_sso_id, nk.SSO_INTEGRATION, self.tenant_id
                ),
            ),
        )

    @property
    def edges(self) -> Iterable[Edge]:
        return ()


def _log_warnings(warnings: Iterable[BuildWarning]) -> None:
    for warning in warnings:
        logger.warning("%s", warning)


@app.asset(
    node=NODE_DEFS[NodeKind.SERVICE_PROVIDER],
    edges=edge_defs(
        NodeKind.SERVICE_PROVIDER,
        native_kind=nk.SSO_INTEGRATION,
        account_kinds=[nk.ACCOUNT],
    ),
)
class SAMLServiceProvider(SAMLSSOBase):
    """The Jamf SP with every edge that leaves it."""

    @property
    def as_node(self) -> SamlNode | None:
        facts = self.facts
        if facts is None:
            if self.is_saml:
                logger.warning(
                    "Jamf SAML facts skipped: the SP entity ID or the IdP issuer "
                    "was not observed (%s)",
                    "; ".join(self._metadata_errors) or "no metadata error",
                )
            return None
        return sp.service_provider_node(SAML, facts.provider)

    @property
    def edges(self) -> Iterable[Edge]:
        facts = self.facts
        if facts is None:
            return ()
        edges, warnings = sp.service_provider_edges(
            SAML,
            facts.provider,
            native=facts.native,
            trusted_issuer=facts.issuer,
            routes=facts.routes,
            accounts=facts.accounts,
        )
        _log_warnings(warnings)
        return edges


@app.asset(
    node=NODE_DEFS[NodeKind.ACCOUNT_RESOLUTION_RULE],
    edges=edge_defs(NodeKind.ACCOUNT_RESOLUTION_RULE, native_kind=nk.SSO_INTEGRATION),
)
class SAMLAccountResolutionRule(SAMLSSOBase):
    """The rule that matches an assertion to a Jamf account."""

    @property
    def as_node(self) -> SamlNode | None:
        facts = self.facts
        if facts is None or not facts.provider.rules:
            return None
        return sp.account_resolution_rule_node(
            SAML, facts.provider, facts.provider.rules[0]
        )


@app.asset(node=NODE_DEFS[NodeKind.ACCOUNT_RESOLUTION_FIELD])
class SAMLAccountResolutionField(SAMLSSOBase):
    """The Jamf `username` field, which an exceptional username mapping reads."""

    @property
    def as_node(self) -> SamlNode | None:
        facts = self.facts
        if facts is None or not facts.provider.rules:
            return None
        names = render_rule(facts.provider.rules[0].conditions).account_field_names
        if not names:
            return None
        return sp.account_resolution_field_node(SAML, facts.provider, names[0])


@app.asset(node=NODE_DEFS[NodeKind.ISSUER])
class SAMLIssuer(SAMLSSOBase):
    """The upstream issuer that Jamf trusts."""

    @property
    def as_node(self) -> SamlNode | None:
        facts = self.facts
        if facts is None:
            return None
        return shared.issuer_node(SAML, self.tenant_node_id, facts.issuer)


@app.asset(node=NODE_DEFS[NodeKind.ASSERTION_CONSUMER_SERVICE])
class SAMLAssertionConsumerService(SAMLSSOBase):
    """One ACS endpoint of the Jamf SP. The source adds one record for each endpoint."""

    saml_acs: AssertionConsumerService | None = Field(alias="samlAcs", default=None)

    @property
    def as_node(self) -> SamlNode | None:
        facts = self.facts
        if facts is None or self.saml_acs is None:
            return None
        route = self._route(self.saml_acs, facts.sp_entity_id)
        return shared.acs_node(SAML, self.tenant_node_id, route)
