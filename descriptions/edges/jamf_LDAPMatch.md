## General Information

The traversable jamf_LDAPMatch edge represents a directory identity correlation established through a Jamf Pro Cloud Identity Provider lookup. It connects an idp user to its matching enabled jamf_Account, or an idp group to its matching jamf_Group. Lookups use enabled cloud providers associated with the Jamf principal's LDAP server entries.

A single valid search result establishes a match. When multiple results are returned, user matches require a matching email attribute and group matches require a matching group name. The returned Azure UUID is matched against the source node's objectid, and the destination is matched by the Jamf node ID. This edge records directory lookup evidence; successful authentication and effective access require separate validation.
