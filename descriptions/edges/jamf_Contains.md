## General Information

The traversable `jamf_Contains` edge represents a structural containment relationship where the source node contains the
target resource. The Jamf tenant contains all top-level resources, while sites contain resources scoped to that site.
Resources not assigned to a specific site are contained directly by the tenant. ComputerUser nodes are only contained by
sites or tenant indirectly through their parent computer, not directly by Contains edges.
