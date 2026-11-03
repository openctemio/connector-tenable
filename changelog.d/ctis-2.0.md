### Upgrade notes: reports are CTIS 2.0; upgrade together with the platform

- The connector now writes CTIS 2.0 documents only. A platform older than the CTIS 2.0 release rejects them, and a 2.0 platform rejects the previous reports, so upgrade the connector and the platform in the same maintenance window. There is no compatibility mode.
- Built on sdk-go with CTIS 2.0 (`github.com/openctemio/ctis/v2`) and the contract module; no configuration change.

### Changed: what a report carries

- `metadata.id` no longer holds the platform command id. The client stamps a producer UUIDv7 and the command binding stays in the transport. The documents carry `channel: integration`, the tool technique `va` and Tenable's own names as `source_refs`.
- Asset values are canonical. A finding on a port belongs to a `service` asset (`host:port/transport`) that its host `exposes`; a host-level finding belongs to the host. A host with a DNS name gets an `ip_address` asset linked by `resolves_to`.
- CVEs are `vulnerability.ids`, ratings are `scores[]` (CVSS v3/v2/v4 with version and vector, VPR as a `vendor` score, EPSS), exploit availability is a `public_exploit` threat signal, the patch date is `remediation.patch_published_at`, plugin output is a `raw_text` evidence item, and an accepted risk is a suppression.
