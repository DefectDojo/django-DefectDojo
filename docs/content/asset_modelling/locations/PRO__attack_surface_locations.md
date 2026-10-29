---
title: "Domain, IP Address and Certificate Locations"
description: "Domain, IP address and certificate locations describe an organization's internet-facing attack surface: the DNS names, addresses and TLS certificates that parsers and connectors report"
weight: 11
audience: pro
---

Three location types describe what an organization exposes to the internet: **Domains**, **IP Addresses** and **Certificates**. They sit beside URLs, Dependencies, Source Code, Cloud Resources and Container Images, and parsers and connectors that support them report them.

> These location types require the Locations feature and are enabled as the **Attack Surface Discovery** flag (beta) on the [Feature Flags page](/admin/feature_flags/pro__feature_flags/). Domains, IP addresses and certificates reported while the flag is off are still stored, and they appear as soon as the flag is turned on.

## What Each Type Records

### Domains

A domain location is a DNS name: an apex domain such as `example.com`, a subdomain such as `api.example.com`, or a wildcard such as `*.example.com`.

- **Identity** is the name in lowercase, without a trailing dot, with internationalized names in their ASCII form. `WWW.Example.com.` and `www.example.com` are one location, and so are `bücher.example` and `xn--bcher-kva.example`.
- A wildcard is its own location. A certificate for `*.example.com` covers something different from one for `example.com`.
- **Apex domain** is the registrable domain the name sits under. When the reporting source knows it, that value is used. Otherwise DefectDojo takes the last two labels of the name, or the last three under a country code such as `co.uk`. The apex groups names on the location map and does not decide ownership.
- An IP address is never stored as a domain.

### IP Addresses

An IP location is a single IPv4 or IPv6 address, with no port or scheme.

- **Identity** is the address in canonical form, so `2001:DB8::1` and `2001:db8:0:0::1` are one location. An IPv4 address written in IPv6 form, such as `::ffff:198.51.100.7`, is stored as the IPv4 address.
- Loopback, link-local, unspecified and multicast addresses are not stored, because they do not name a machine anyone can reach.
- Each address records whether it is **internet routable**. Private, reserved, documentation and shared address ranges are not. When the source knows them, each address also records the **ASN** that announces it, the ASN's **organization**, the registry **network** it belongs to, and the cloud or CDN **provider** that serves it. These details change when a provider reassigns an address, so the most recent report that includes a detail replaces the stored value.

A web service on an address is still a URL location. An IP location is for sources that report bare addresses, such as cloud inventories, DNS answers and recon tools.

### Certificates

A certificate location is one X.509 certificate.

- **Identity** is the SHA-256 fingerprint of the certificate, shown as `sha256:` followed by 64 hex characters. Fingerprints with colons or in upper case are accepted and stored in one form.
- Each certificate records its **subject common name**, **issuer**, **serial number**, **validity window** and **subject alternative names**. Validity times without a time zone are read as UTC. Subject alternative names are kept once each, up to 253 characters per name and 500 names per certificate.
- A certificate does not change, so a later report only fills in details an earlier one did not have.

## How They Relate to Other Locations and Assets

- **Domains and hosts.** A host location is a machine known by the name it reports, stored exactly as reported. A domain location is a DNS name, normalized. The same text can be both, and DefectDojo does not merge them.
- **IP addresses and URLs.** A URL keeps its own host. DefectDojo does not create an IP location for every URL host.
- **Assets.** Connectors that model each internet-facing host or domain as its own asset keep doing so. These location types describe the names, addresses and certificates themselves, and an asset can carry any number of them.

## Where to Find Them

- **Domains**, **IP Addresses** and **Certificates** under **Explore > Attack Surface** in the sidebar each list the locations of one type.
- **All Locations** lists domains, IP addresses and certificates with their type, alongside every other location.
- The asset **location map** draws three regions: **Domains** grouped by apex domain, **IP Addresses** grouped by network, and **Certificates** grouped by issuer and named by their common name. A group the source did not report, such as an address with no known network, collects under a placeholder.
- The general locations resource returns them at `/api/v3/locations?type=domain`, `?type=ip` and `?type=cert`.

These locations are created by imports and connectors. There is no form to add one by hand.

## Reporting Them from a Parser or Connector

Parsers build them with `LocationData.domain()`, `LocationData.ip()` and `LocationData.cert()`, and a finding carries them like any other location. Connectors send typed location items of type `domain`, `ip` or `cert`, either on a finding or as standalone inventory for an Asset; the standalone inventory also needs the **Connector Location Inventory** flag. See [Connector Location Inventory](/connectors/upstream/location_inventory/).

A value that cannot name a location, such as a malformed fingerprint or an address in a domain field, is skipped and the rest of the import continues.
