from unittest.mock import MagicMock

from openhound_jamf.graph import JAMFNode
from openhound_jamf.kinds import edges as ek
from openhound_jamf.kinds import nodes as nk
from openhound_jamf.models.user import InventoryAssignedUser, User


def _lookup() -> MagicMock:
    lookup = MagicMock()
    lookup.tenant_id.return_value = "jamf.example.test"
    lookup.users_by_email.return_value = []
    lookup.users_by_name.return_value = []
    lookup.user_has_computer_link.return_value = False
    lookup.accounts_by_email.return_value = []
    lookup.accounts_by_name.return_value = []
    return lookup


def test_native_user_computer_link_is_explicit_hard_evidence() -> None:
    user = User(
        id=7,
        name="alice",
        full_name="Alice Example",
        email="alice@example.test",
        phone_number="",
        links={"computers": [{"id": 42}]},
    )
    user._lookup = _lookup()

    edge = next(iter(user._assigned_user_edges))

    assert edge.kind == ek.ASSIGNED_USER
    assert edge.properties.match_type == "hard"
    assert edge.properties.confidence == "high"
    assert edge.properties.evidence_source == "jamf_user_links_computers"
    assert edge.properties.match_basis == "jamf_native_id"


def test_inventory_only_user_emits_soft_legacy_node_and_edge() -> None:
    inventory_user = InventoryAssignedUser(
        computer_id="42",
        username="alice",
        realname="Alice Example",
        email="alice@example.test",
    )
    inventory_user._lookup = _lookup()

    node = inventory_user.as_node
    edge = next(iter(inventory_user.edges))

    assert node is not None
    assert node.kinds == [nk.USER]
    assert edge.end.value == node.id
    assert edge.properties.match_type == "soft_legacy"
    assert edge.properties.confidence == "low"
    assert edge.properties.match_basis == "inventory_email"
    assert (
        edge.properties.evidence_source == "jamf_computer_inventory_user_and_location"
    )


def test_unique_inventory_email_match_reuses_collected_user_node() -> None:
    lookup = _lookup()
    lookup.users_by_email.return_value = [(7,)]
    inventory_user = InventoryAssignedUser(
        computer_id="42",
        username="alice",
        email="alice@example.test",
    )
    inventory_user._lookup = lookup

    edge = next(iter(inventory_user.edges))

    assert inventory_user.as_node is None
    assert edge.end.value == JAMFNode.guid("7", nk.USER, "jamf.example.test")
    assert edge.properties.match_type == "soft_legacy"
    assert edge.properties.confidence == "medium"
    assert edge.properties.match_basis == "email"


def test_inventory_fallback_is_suppressed_for_existing_hard_pair() -> None:
    lookup = _lookup()
    lookup.users_by_email.return_value = [(7,)]
    lookup.user_has_computer_link.return_value = True
    inventory_user = InventoryAssignedUser(
        computer_id="42",
        username="alice",
        email="alice@example.test",
    )
    inventory_user._lookup = lookup

    assert inventory_user.as_node is None
    assert list(inventory_user.edges) == []


def test_blank_email_uses_distinct_usernames_for_inventory_identity() -> None:
    lookup = _lookup()
    users = [
        InventoryAssignedUser(computer_id=str(index), username=name, email="  ")
        for index, name in enumerate(("alice", "bob"), start=1)
    ]
    for user in users:
        user._lookup = lookup

    nodes = [user.as_node for user in users]
    edges = [next(iter(user.edges)) for user in users]

    assert all(node is not None for node in nodes)
    assert nodes[0].id != nodes[1].id
    assert [edge.end.value for edge in edges] == [node.id for node in nodes]
    assert [edge.properties.match_basis for edge in edges] == [
        "inventory_username",
        "inventory_username",
    ]
    lookup.users_by_email.assert_not_called()


def test_blank_inventory_identity_emits_no_user_or_edge() -> None:
    user = InventoryAssignedUser(
        computer_id="42", username=" ", email="\t", realname="  "
    )
    user._lookup = _lookup()

    assert user.as_node is None
    assert list(user.edges) == []
