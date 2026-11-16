<p align="center">
  <a href="https://specterops.io" target="_blank">
    <img alt="A project powered by SpecterOps - Creators of BloodHound" src="https://raw.githubusercontent.com/SpecterOps/OpenHound/refs/heads/main/.github/GitHub-Header.png" width="100%" style="max-width: 100%;">
  </a>
</p>

<h4 align="center">
  Jamf collector for OpenHound
</h4>

<!-- Standard shields, please do not remove -->
<p align="center">
  <a href="https://slack.specterops.io"><img src="https://custom-icon-badges.demolab.com/badge/Slack-BloodHound%20Gang-4A154B?logo=slack&logoColor=fff" alt="Slack"/></a>
  <a href="https://reddit.com/r/SpecterOpsCommunity"><img src="https://img.shields.io/badge/Reddit-r/SpecterOpsCommunity-FF4500?logo=reddit&logoColor=white" alt="SpecterOps on Reddit"/></a>
  <a href="https://github.com/specterops"><img src="https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fspecterops%2F.github%2Fmain%2Fconfig%2Fshield.json&style=flat" alt="Sponsored by SpecterOps"/></a>
</p>


<p align="center">
  <a href="https://x.com/SpecterOps"><img src="https://img.shields.io/twitter/follow/SpecterOps?style=social" alt="@SpecterOps on Twitter"/></a>
  <a href="https://www.linkedin.com/company/specterops/"><img src="https://custom-icon-badges.demolab.com/badge/LinkedIn-0A66C2?logo=linkedin-white&logoColor=fff" alt="Connect on LinkedIn"/></a>
  <a href="https://infosec.exchange/@specterops"><img src="https://img.shields.io/mastodon/follow/109314317500800201?domain=https%3A%2F%2Finfosec.exchange&style=social" alt="Connect on Mastodon"/></a>
</p>

---

## About

OpenHound is a standardized framework for building and running OpenGraph collectors and converters. It is built in
Python and powered by the [Data Load Tool (DLT)](https://dlthub.com/docs/intro) library, giving you a consistent
workflow to collect, process, and convert data from any source into BloodHound-compatible graphs.

The openhound-jamf extension collects Jamf Pro resources and transforms these into usable nodes and edges for
BloodHound.

[![Python Version](https://img.shields.io/badge/Python-3.13-brightgreen.svg)](#about)

## Getting Started

Follow the OpenHound docs to get started:

- [OpenHound Documentation](https://bloodhound.specterops.io/openhound/overview)

## SAML metadata origins

The collector writes SAML nodes and edges for the Jamf SSO setup. To do this, it
reads the SAML metadata of Jamf and of the identity provider (IdP) from the URLs
in the Jamf SSO settings. The Jamf origin is always allowed. For an IdP on another
origin, you must allow that origin yourself. Set `saml_metadata_allowed_origins` to
a comma-separated list of HTTPS origins, with no path:

```toml
[sources.jamf]
saml_metadata_allowed_origins = "https://example.okta.com,https://login.example.com"
```

The environment variable form is
`SOURCES__JAMF__SAML_METADATA_ALLOWED_ORIGINS`. If you do not set it, the collector
does not fetch IdP metadata from another origin. Then it writes no SAML facts for
that IdP, and the log names this setting.

## Containers

Each new release publishes multi-architecture images to GHCR with versions
matching the automatically generated PyPI package version:

- Scheduler: `ghcr.io/specterops/openhound-jamf:latest` or `:<version>`
- CLI: `ghcr.io/specterops/openhound-jamf:latest-cli` or `:<version>-cli`

Use the [Docker Compose deployment guide](docker-compose/README.md) to configure
and run the non-root BHE scheduler with persistent storage and local preflight
checks. To inspect CLI usage:

```sh
docker run --rm ghcr.io/specterops/openhound-jamf:latest-cli --help
```
