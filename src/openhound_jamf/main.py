from dlt.extract.source import DltSource
from openhound.core.app import OpenHound
from openhound.core.collect import CollectContext
from openhound.core.convert import ConvertContext
from openhound.core.preproc import PreProcContext

from openhound_jamf.lookup import JamfLookup
from openhound_jamf.transforms import transforms

app = OpenHound("jamf", source_kind="jamf", help="OpenGraph collector for JAMF Pro")


@app.collect()
def collect(ctx: CollectContext) -> DltSource:
    """Register a Typer CLI command that collects JAMF resources and stores them (filtered) on disk.

    Args:
        ctx (CollectContext): Returns DLT pipeline context.
    """
    from openhound_jamf.source import source as jamf_source

    return jamf_source()


@app.preproc(transformer=transforms)
def preproc(ctx: PreProcContext):
    resources = {
        "account_details": "account_details",
        "account_group_details": "account_group_details",
        "computers": "computers",
        "policy_details": "policy_details",
        "script_details": "script_details",
        "api_integrations": "api_integrations",
        "api_roles": "api_roles",
        "computerextensionattributes": "computerextensionattributes",
        "sites": "sites",
        "user_details": "user_details",
        "tenant": "tenant",
        "sso": "sso",
    }
    return resources


@app.convert(lookup=JamfLookup)
def convert(ctx: ConvertContext) -> tuple[DltSource, dict]:
    """Register a Typer CLI command that converts JAMF resources to OpenGraph files

    Args:
        ctx (CollectContext): Returns DLT pipeline context.
    """
    from openhound_jamf.source import source as jamf_source

    return jamf_source(), {}
