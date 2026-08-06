from typing import cast
from unittest.mock import MagicMock

from openhound.core.models.entries_dataclass import EdgePath
from openhound.core.models.entries_dataclass import Node as BaseNode

from openhound_jamf.graph import JAMFNode
from openhound_jamf.kinds import edges as ek
from openhound_jamf.kinds import nodes as nk
from openhound_jamf.lookup import JamfLookup
from openhound_jamf.models.account import Account
from openhound_jamf.models.user import User


TENANT_ID = "Tenant.Example.com"


def _make_account() -> Account:
    lookup = MagicMock(spec=JamfLookup)
    lookup.tenant_id.return_value = TENANT_ID
    account = Account(
        id=7,
        name="alice",
        full_name="Alice Smith",
        email="Stored.User@Example.com",
        enabled="Enabled",
        access_level="Full Access",
        privilege_set="Administrator",
        directory_user=False,
    )
    account._lookup = cast(JamfLookup, lookup)
    return account


def _make_user(lookup: MagicMock | None = None) -> User:
    if lookup is None:
        lookup = MagicMock(spec=JamfLookup)
        lookup.tenant_id.return_value = TENANT_ID
        lookup.accounts_by_name.return_value = []
        lookup.accounts_by_email.return_value = []
    user = User(
        id=9,
        name="alice",
        full_name="Alice Smith",
        email="alice@example.com",
        phone_number="555-0100",
    )
    user._lookup = cast(JamfLookup, lookup)
    return user


def test_guid_uppercases_existing_uuid():
    """Keep existing graph identities when ingest stops normalizing ObjectIDs."""
    assert (
        JAMFNode.guid("mixedCaseSourceId", nk.ACCOUNT, TENANT_ID)
        == BaseNode.guid("mixedCaseSourceId", nk.ACCOUNT, TENANT_ID).upper()
    )


def test_node_id_is_uppercase():
    """Ensure emitted JAMF nodes satisfy the uppercase ObjectID requirement."""
    node_id = _make_account().as_node.id

    assert node_id == node_id.upper()


def test_id_edge_paths_reference_uppercase_node_ids():
    """Ensure uppercasing ObjectIDs does not disconnect edge endpoints."""
    account = _make_account()
    admin_edge = next(edge for edge in account.edges if edge.kind == ek.ADMIN_TO)
    edge_start = cast(EdgePath, admin_edge.start)
    edge_end = cast(EdgePath, admin_edge.end)

    assert (edge_start.value, edge_end.value) == (
        account.as_node.id,
        account.tenant_node_id,
    )


def test_name_property_is_uppercased():
    """Keep existing graph names when ingest stops normalizing `name`."""
    account = _make_account()

    assert account.as_node.properties.name == "ALICE"


def test_displayname_property_is_not_uppercased():
    """`displayname` is explicitly out of scope for uppercasing."""
    account = _make_account()

    assert account.as_node.properties.displayname == "alice"


def test_matched_name_edges_resolve_after_uppercasing_name():
    """Uppercasing `name` on the graph node must not break the internal
    User -> Account name-match edge, which queries raw (pre-transform)
    lookup data via `self.name` on the Pydantic model, not the uppercased
    node properties.
    """
    lookup = MagicMock(spec=JamfLookup)
    lookup.tenant_id.return_value = TENANT_ID
    lookup.accounts_by_name.return_value = [(7,)]
    lookup.accounts_by_email.return_value = []
    user = _make_user(lookup=lookup)

    # The node-level name is uppercased...
    assert user.as_node.properties.name == "ALICE"

    # ...but the internal lookup still matches on the raw (mixed-case) name.
    matched_edges = list(user._matched_name_edges)
    lookup.accounts_by_name.assert_called_once_with("alice")
    assert len(matched_edges) == 1
    assert matched_edges[0].kind == ek.MATCHED_NAME
