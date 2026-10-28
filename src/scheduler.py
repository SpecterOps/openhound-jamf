"""Start the Jamf BloodHound Enterprise scheduler."""

import logging

import dlt
from openhound.scheduler.service import Service

logger = logging.getLogger(__name__)


def start() -> None:
    """Resolve DLT configuration and poll BHE for collection jobs."""
    collector_name = dlt.config["destination.bloodhoundenterprise.collector_name"]
    logger.info("Initializing service for collector '%s'.", collector_name)
    service = Service(
        bhe_uri=dlt.secrets["destination.bloodhoundenterprise.url"],
        token_id=dlt.secrets["destination.bloodhoundenterprise.token_id"],
        token_key=dlt.secrets["destination.bloodhoundenterprise.token_key"],
        collector_name=collector_name,
    )
    service.start()


if __name__ == "__main__":
    start()
