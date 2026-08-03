from typing import cast
from unittest.mock import MagicMock

from openhound.core.models.entries_dataclass import EdgePath
from openhound.core.models.entries_dataclass import Node as BaseNode

from openhound_jamf.graph import JAMFNode
from openhound_jamf.kinds import edges as ek
from openhound_jamf.kinds import nodes as nk
from openhound_jamf.lookup import JamfLookup
from openhound_jamf.models.account import Account


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
