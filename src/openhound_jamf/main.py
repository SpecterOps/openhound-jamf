import dlt
import typer
from dlt.extract.source import DltSource
from openhound.core.app import OpenHound
from openhound.core.collect import CollectContext
from openhound.core.convert import ConvertContext
from openhound.core.preproc import PreProcContext

from openhound_jamf.lookup import JamfLookup
from openhound_jamf.transforms import transforms

app = OpenHound("jamf", source_kind="jamf", help="OpenGraph collector for JAMF Pro")


def nodes_only_enabled() -> bool:
    """Read the Jamf preview setting with support for a top-level TOML key."""
    configured = dlt.config.get("sources.jamf.NodesOnly", bool)
    if configured is None:
        configured = dlt.config.get("NodesOnly", bool)
    return configured is True


@app.collect()
def collect(ctx: CollectContext) -> DltSource | None:
    """Register a Typer CLI command that collects JAMF resources and stores them (filtered) on disk.

    Args:
        ctx (CollectContext): Returns DLT pipeline context.
    """
    if nodes_only_enabled():
        from openhound_jamf.preview import print_projected_nodes

        if ctx.pipeline.resources:
            raise typer.BadParameter(
                "NodesOnly counts the nodes in a Jamf collection. Omit the resource list."
            )
        print_projected_nodes()
        return None

    from openhound_jamf.source import source as jamf_source

    return jamf_source()


@app.preproc(transformer=transforms)
def preproc(ctx: PreProcContext):
    """Return the collected resource tables required to build the Jamf lookup database."""
    resources = {
        "account_details": "account_details",
        "account_group_details": "account_group_details",
        "computers": "computers",
        "policy_details": "policy_details",
        "script_details": "script_details",
        "api_integrations": "api_integrations",
        "api_roles": "api_roles",
        "cloud_integrations": "cloud_integrations",
        "cloud_integration_details": "cloud_integration_details",
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
    if nodes_only_enabled():
        raise typer.BadParameter(
            "NodesOnly prints the count during collect jamf. Set NodesOnly = false to convert a graph."
        )

    from openhound_jamf.source import source as jamf_source

    return jamf_source(), {}
