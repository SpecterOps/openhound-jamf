from dataclasses import asdict
from unittest.mock import MagicMock

import pytest
from pydantic import ValidationError

from openhound_jamf.lookup import JamfLookup
from openhound_jamf.models.group import Group


def make_group(**extra):
    group = Group(
        id=10,
        name="Test Directory Group",
        access_level="Full Access",
        privilege_set="Administrator",
        **extra,
    )
    lookup = MagicMock(spec=JamfLookup)
    lookup.tenant_id.return_value = "jamf.example.com"
    group._lookup = lookup
    return group


@pytest.mark.parametrize(
    "extra,expected",
    [
        ({}, False),
        ({"ldap_server": None}, False),
        ({"ldap_server": {}}, False),
        ({"ldap_server": []}, False),
        ({"ldap_server": [None, {}]}, False),
        ({"ldap_server": {"id": 101, "name": "Test Provider"}}, True),
        ({"ldap_server": [{"id": "101"}, {"id": 102}]}, True),
        ({"ldap_servers": [{"id": 101}]}, True),
    ],
)
def test_directory_group_export(extra, expected):
    group = make_group(**extra)
    # The normalized collection representation must survive conversion too.
    restored = Group.model_validate(group.model_dump(mode="json"))
    restored._lookup = group._lookup
    node = asdict(restored.as_node)
    assert node["properties"]["directory_group"] is expected
    assert node["kinds"] == ["jamf_Group"]
    assert "ldap_server" not in node["properties"]


@pytest.mark.parametrize("value", ["invalid", [{"name": "Missing ID"}], [42]])
def test_malformed_directory_associations_are_rejected(value):
    with pytest.raises(ValidationError):
        make_group(ldap_server=value)
