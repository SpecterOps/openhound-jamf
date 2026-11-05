## General Information

The non-traversable jamf_CloudIntegrationLink edge represents the existence of a cloud integration configuration within a Jamf Pro tenant and its connection to the configured Azure/Entra tenant. It connects jamf_Tenant to jamf_CloudIntegration, and jamf_CloudIntegration to AZTenant. These relationships provide configuration context and are excluded from BloodHound pathfinding.

Links are created for both enabled and disabled Azure integrations. The Azure tenant is resolved by matching AZTenant.objectid to the tenantId returned in the Azure configuration details. If those details are unavailable or the tenant UUID is invalid, only the link from the Jamf tenant to the integration is emitted.
