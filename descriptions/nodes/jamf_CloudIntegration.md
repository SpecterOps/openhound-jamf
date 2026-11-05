## Description

Represents a cloud identity provider configured in a Jamf Pro tenant. When enabled, the provider supports directory lookups that correlate idp users and groups with Jamf directory accounts and groups. Nodes are collected for both enabled and disabled integrations and include the provider identity, enabled status, and available identity provider and attribute-mapping configuration. Non-traversable jamf_CloudIntegrationLink edges connect the configuration to its Jamf tenant and, when valid configuration details are available, the cloud identity provider.
