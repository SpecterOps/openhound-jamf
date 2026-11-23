from pathlib import Path
from tempfile import TemporaryDirectory

import dlt
import duckdb
from openhound.sources.resource_files.source import resource_files

from openhound_jamf.lookup import JamfLookup
from openhound_jamf.main import app
from openhound_jamf.models.cloudintegration import CloudIntegrationSnapshot
from openhound_jamf.source import source

NODE_RESOURCES = (
    "account_details",
    "account_group_details",
    "api_integrations",
    "computers",
    "sites",
    "sso",
    "tenant",
    "user_details",
)
LOOKUP_RESOURCES = ("tenant", "cloud_integrations")


class _PreviewLookup(JamfLookup):
    def client_permissions(self, client_id: int) -> list[tuple[str]]:
        """Use an empty privilege list because API client IDs do not depend on it."""
        return []


def print_projected_nodes() -> None:
    """Collect Jamf node inputs in an isolated workspace and report unique IDs."""
    with TemporaryDirectory(prefix="openhound-jamf-preview-") as directory:
        workspace = Path(directory)
        pipelines_dir = str(workspace / "pipelines")
        raw_output = workspace / "raw"
        raw_path = raw_output / app.name
        lookup_file = workspace / "lookup.duckdb"

        jamf_source = source(nodes_only=True).with_resources(
            *dict.fromkeys((*NODE_RESOURCES, *LOOKUP_RESOURCES))
        )
        collector = dlt.pipeline(
            pipeline_name="jamf_preview_collect",
            pipelines_dir=pipelines_dir,
            dataset_name=app.name,
            destination=dlt.destinations.filesystem(bucket_url=str(raw_output)),
        )
        try:
            collected = collector.run(
                jamf_source, write_disposition="replace", loader_file_format="jsonl"
            )
            collected.raise_on_failed_jobs()
        finally:
            collector.deactivate()

        # Empty resources have no raw files.
        tables = {
            name
            for name in jamf_source.selected_resources
            if any((raw_path / name).rglob("*.jsonl.gz"))
        }
        if "tenant" not in tables:
            raise RuntimeError(
                "Jamf preview could not read the collected tenant resource"
            )

        preprocessor = dlt.pipeline(
            pipeline_name="jamf_preview_preprocess",
            pipelines_dir=pipelines_dir,
            dataset_name=app.name,
            destination=dlt.destinations.duckdb(str(lookup_file)),
        )
        try:
            loaded = preprocessor.run(
                resource_files(
                    raw_path,
                    {name: name for name in LOOKUP_RESOURCES if name in tables},
                ),
                write_disposition="replace",
            )
            loaded.raise_on_failed_jobs()
        finally:
            preprocessor.deactivate()

        with duckdb.connect(str(lookup_file)) as connection:
            models = {
                resource.table_name: resource.validator.model
                for resource in jamf_source.selected_resources.values()
                if getattr(resource.validator, "model", None) in app.assets
                and resource.table_name in tables
            }
            node_ids = set()
            lookup = _PreviewLookup(connection)
            cloud_table = "cloud_integrations"
            raw_tables = {name: name for name in models}
            if cloud_table in tables:
                raw_tables[cloud_table] = cloud_table
            resources = resource_files(raw_path, raw_tables).resources
            if cloud_table in resources:
                tenant_id = lookup.tenant_id()
                if not tenant_id:
                    raise RuntimeError(
                        "Jamf preview could not read the tenant identity"
                    )
                for row in resources[cloud_table]:
                    snapshot = CloudIntegrationSnapshot.model_validate(row)
                    for provider in snapshot.results:
                        node_id = provider.graph_node_id(tenant_id)
                        if node_id is not None:
                            node_ids.add(node_id)

            for table, model in models.items():
                for row in resources[table]:
                    asset = model(**row)
                    asset._lookup = lookup
                    asset._extras = {}
                    node = asset.as_node
                    if node is not None:
                        node_ids.add(node.id)

    print(f"{len(node_ids)} Projected Nodes")
