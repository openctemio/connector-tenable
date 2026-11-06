# Tenable.sc connector

The connector can pull hosts, vulnerabilities and plugin metadata from a
Tenable Security Center (Tenable.sc) inside your network and send them to
OpenCTEM. The connector is the only component that talks to Tenable.sc. The
Tenable API keys stay on the connector: OpenCTEM never receives, stores or
forwards them, and needs no route into your network.

Design: api `docs/rfcs/RFC-047-tenable-sc-sensor-connector.md` in
`openctemio/openctem`.

## How it works

1. In OpenCTEM, a Tenable.sc integration names this connector and an
   **instance name** (for example `sc-prod`). That name is the only thing the
   platform knows about your Tenable.sc.
2. On a schedule, or when someone clicks "Sync now", the platform queues a
   `connector_sync` command for this connector.
3. The connector checks the command against the local policy
   (`checks.allow` must allow `connector_sync`, and `tools.allow` must allow
   `tenable_sc` if those lists are set) and against this connector's own
   allow-list. It then reads Tenable.sc and pushes CTIS reports bound to the
   command.

The platform can ask for an incremental or full sync, a minimum severity and
a subset of repositories. It cannot send a URL, a header, a query or a
filter, and it can only narrow the repositories you allowed.

## Configuration

The config file is written by the network owner and mounted read-only:

```yaml
# /etc/openctem/connectors/tenable-sc.yaml  (root-owned, 0640, read-only mount)
apiVersion: openctem.io/connector-tenable-sc/v1
instances:
  - name: sc-prod                       # what the OpenCTEM integration names
    url: https://sc.example.com          # https only
    ca_file: /etc/openctem/tenable-ca.pem          # optional; replaces the system roots
    pin_spki_sha256: ["kV2x...="]                   # optional; base64 SHA-256 of the SubjectPublicKeyInfo
    access_key_file: /run/secrets/tenable_sc_access_key
    secret_key_file: /run/secrets/tenable_sc_secret_key
    allow:
      operations: [sync]                # add "scan" to let OpenCTEM launch scans
      repositories: [5, 7]              # required: nothing is read without it
      # Only with operations: [sync, scan]:
      scan_policies: [1000003]          # policies a launched scan may use (required for scan)
      scan_repositories: [5]            # repositories its results may go to (required for scan)
      scan_zones: [2]                   # optional; 0 is Tenable's default zone
      max_targets_per_scan: 512         # addresses per scan, CIDRs counted by size
      max_scan_seconds: 28800           # longest scan the platform may ask for
    limits:
      page_size: 1000                   # 50..5000
      max_records: 1000000              # per sync, all queries
      max_response_bytes: 67108864      # per HTTP response (1 MiB..512 MiB)
      requests_per_second: 5            # at most 50
```

Location: `-config`, else `TENABLE_SC_CONFIG`, else
`/etc/openctem/connectors/tenable-sc.yaml` when it exists. Without a config
the connector refuses to start.

For a single instance, environment variables work too (instance name
`default`):

| Variable | Meaning |
|---|---|
| `TENABLE_SC_URL` | `https://` base URL |
| `TENABLE_SC_ACCESS_KEY_FILE`, `TENABLE_SC_SECRET_KEY_FILE` | key files (recommended) |
| `TENABLE_SC_ACCESS_KEY`, `TENABLE_SC_SECRET_KEY` | raw keys (accepted with a warning: environment values leak more easily) |
| `TENABLE_SC_CA_FILE` | CA file |
| `TENABLE_SC_REPOSITORIES` | allowed repository ids, comma-separated (required) |
| `TENABLE_SC_OPERATIONS` | allowed operations (default `sync`) |

### Fail closed

The connector refuses to start when the config has an unknown key, a non-https
URL, a missing or world-writable config or key file, a key with characters an
API key cannot have, a duplicate instance name, no repositories, or both a
file and `TENABLE_SC_URL`. There is no option to skip TLS verification.

## TLS and network

- TLS 1.2 or later, with the system roots or your `ca_file`, plus optional
  SPKI pins. The host name is always verified.
- Redirects are refused, so the key header never goes to another host.
- Private addresses are allowed (Tenable.sc is internal). Loopback,
  link-local, cloud metadata, multicast and unspecified addresses are refused.
- Requests are rate limited. 429, 502, 503 and 504 are retried with backoff
  (honouring `Retry-After`, at most 60 s, 5 attempts). 401 and 403 are never
  retried.

## Scan launch (connector_scan)

When an instance allows `scan`, the connector runs `connector_scan` commands
from OpenCTEM scan runs (OpenCTEM owns the schedule; nothing is scheduled in
Tenable.sc). Before any Tenable.sc call the connector checks, and refuses the
whole job on any violation:

- the policy, repository and zone are in `scan_policies`,
  `scan_repositories` and `scan_zones`;
- every target is one IP address, an IPv4 range of /16 or narrower, an IPv6
  range of /120 or narrower, or a host name (no URLs, ports or lists), and
  the targets cover at most `max_targets_per_scan` addresses;
- no target is loopback, link-local, cloud metadata, multicast or reserved;
- every target passes the local policy (`SENSOR_LOCAL_POLICY`, `SENSOR_ALLOWED_RANGES`), again here
  after the job admission.

It then creates one scan named `openctem-<command id>` (the targets as its IP
list, `timeoutAction: import`), launches it, polls the scan result every 30
seconds, reads the result's findings and hosts and pushes them bound to the
command, and deletes the scan definition it created (the results stay). It
never edits, launches or deletes any other scan. The reports say coverage
`full` only when the scan completed and its import finished; anything else
(error, partial, stopped, no results, past `max_scan_seconds` plus 30 minutes
for the import, when it is stopped) is `partial`, which never closes a
finding by absence. A cancelled command stops the scan.

**Tracking.** While the scan runs, the connector reports the checks Tenable.sc
completed as liveness on its heartbeat, so OpenCTEM can tell a slow scan from
a stuck one. When it ends, the command result says how each target ended (the
per-target outcome of the CTIS profile): `done` when the scan result lists the host (an
address, an address inside a range, or a host by its DNS name; a live host
with no findings counts), `failed: unreachable` when a scan that completed and
imported does not list it (it did not reply; this is never read as "nothing
found"), and `unfinished` otherwise (a partial, stopped or timed-out scan).
The result also carries the scan's own `total_ips`/`completed_ips` counters.

**Refused imports fail.** When Tenable.sc does not import the result, the
command fails with the reason instead of completing with no findings:

- import `Blocked` (the import would exceed the IP licence): the error starts
  with `IMPORT_BLOCKED`, carries `scan_result_id=<id>` and the licensed and
  active counts. Nothing was imported. OpenCTEM imports that result again
  later with `reimport_scan_result_id` (`POST /rest/scanResult/{id}/import`)
  once the licence guard sees capacity; it does not scan again;
- import `Error`, or scan status `Error` with nothing imported.

**Scan duration.** `maxScanTime` is sent in whole hours (rounded up, at least
1): the user guide names the setting "Max scan duration (hours)". The
connector also stops the scan itself at `max_scan_seconds` plus 30 minutes.
When a scan reaches Tenable.sc's own limit, Tenable.sc creates a rollover
scan; the connector deletes every rollover scan whose name contains its
`openctem-<command id>`.

**Restarts.** A command handed back to the connector after a restart has the
same id, so the connector first looks for a scan result and a scan definition
named `openctem-<command id>` (a result only in the job's repository). It
follows that scan result instead of launching a second scan, launches a
definition it had created but not launched, and deletes the definition at
the end as usual. The lookup reads `GET /rest/scanResult` and
`GET /rest/scan`; when the user may not list them, the connector launches as
before.

**Licence-aware coverage (Beta).** OpenCTEM can rotate a large estate through
a smaller IP licence in batches (off by default; enabled per connector by an
organization administrator who confirms the customer's Tenable licence terms
allow it). The connector supports it with:

- *Licence guard.* A coverage batch carries `licence_guard {new_addresses,
  headroom}`. Before creating anything the connector reads the licence: on
  6.9 and later `GET /rest/v1/license` (`status`, `blades.sc.limit`,
  `blades.sc.used`), because Tenable deprecated the licence fields of
  `/rest/system` in 6.9.0; before 6.9, or when that read fails,
  `GET /rest/status`. It launches only when the licence status is `Valid`
  (`Exceeded`, `Locked` and `Expired` are refused with the status) and
  `licensed - active` covers the batch's new addresses (at most the
  addresses it covers) plus the headroom; otherwise the command fails with
  `LICENCE_CAPACITY: …` and OpenCTEM tries again later. Without licence
  numbers the guard refuses. The result reports `license_status`,
  `license_source`, `active_ips` (after) and `active_ips_before`.
- *Rotation modes.* How capacity comes back between batches:

  | Mode | What frees the licence | Keys on the sensor | Speed | Status |
  |---|---|---|---|---|
  | off | nothing | user | one licence's worth | |
  | aging (recommended) | 1-day lifetimes on a dedicated universal rotation repository, applied at the nightly cleanup | user | about one batch a day | documented |
  | purge | an imported empty result that removes the previous batch's addresses at once | user (upload and import) | one batch after another | unverified |
  | recycle | a verified replacement repository, then delete the old one | user plus administrator | one batch after another | unverified |

- *Aging* needs nothing on the connector: the administrator creates a
  universal repository with an IP range covering the coverage targets, every
  vulnerability lifetime set to 1 day and group access for the connector
  user, and picks it as the coverage repository. OpenCTEM waits at least 24
  hours plus a margin after each batch, because lifetimes apply only at the
  nightly cleanup.
- *Purge (opt-in, unverified).* Tenable's knowledge base documents that
  importing a `.nessus` file with no host results whose `TARGET` preference
  lists addresses removes those addresses' data from the repository at once.
  It does not work on agent repositories; in a universal repository it
  removes every asset sharing the address; removed data cannot be recovered.
  Add `purge` to `allow.operations` and a `purge` block:

  ```yaml
      allow:
        operations: [sync, scan, purge]
      purge:
        repository_name: openctem-rotation   # must start with "openctem-"
  ```

  A batch with `rotation_mode: purge` scans into that repository. With
  `purge {previous_command_id, targets}` (sent only after the previous
  batch's results were ingested) the connector first finds the previous
  batch's scan result (`openctem-<previous command id>`) in that repository,
  reads the hosts it imported, refuses when any of them is outside the
  previous batch's targets or the repository is an agent repository, builds
  the empty file with exactly those addresses (each one an IP address,
  checked and XML-escaped), uploads it (`POST /rest/file/upload`) and imports
  it (`POST /rest/scanResult/import`) into the rotation repository. It then
  checks with an analysis query that the addresses are gone and that the
  licence count dropped; otherwise the command fails with
  `purge_unverified` and OpenCTEM stalls rotation instead of over-using the
  licence. The API documents no import field for "remove vulnerabilities
  from hosts that do not reply", so none is sent. No administrator key.
- *Recycle (opt-in, unverified).* Tenable.sc has no API that removes chosen
  hosts from a repository, but deleting a repository removes its data. Add
  `recycle` to `allow.operations` and a `recycle` block with **two** names:

  ```yaml
      allow:
        operations: [sync, scan, recycle]
      recycle:
        repository_names: [openctem-rot-a, openctem-rot-b]  # both start with "openctem-"
        admin_access_key_file: /run/secrets/tenable_sc_admin_access_key
        admin_secret_key_file: /run/secrets/tenable_sc_admin_secret_key
  ```

  The administrator creates the first one; at most one of the two holds
  data. With `recycle_repository: true` the connector, with the
  administrator keys: reads the current repository (`typeFields`: IP range
  and lifetimes; `organizations` with `groupAssign`); creates the other name
  from it as a `universal` repository (since 6.8 a new Local repository may
  only be mobile or universal; `trendingDays` is sent only before 6.9); reads
  it back and checks that it is universal with the same IP range, lifetimes
  and group access, that the range covers the batch and that the scanning
  user can see it; and only then deletes the old one. Any failure stops the
  batch with the reason and deletes nothing. If both repositories exist (an
  earlier recycle stopped), the newer one is checked again and the older one
  deleted only when it passes. The replacement does not copy Tenable One
  sync settings, `nessusSchedule` or `correlation`, and its id and uuid
  change, so keep the rotation repositories out of dashboards, reports and
  accept-risk rules. The single `repository_name` form is no longer
  accepted.

The data removal steps follow the API reference and Tenable's knowledge base
and are not yet verified against a real Tenable.sc: try them on a test
instance first.

**Mock for tests.** `cmd/tenablesc-mock` serves a small Tenable.sc API mock
(`internal/connector/tenablesc/scmock`) built from the documented shapes:
scans moving through Queued, Running and Completed, imports finishing or
`Blocked` by the licence (and imported again), dead hosts, the licence
counted by unique addresses holding a non-discovery plugin, repositories in
the documented shape (`typeFields`, `organizations[].groupAssign` for an
administrator, the 6.8 create restriction), HTTP 400 for rejected keys and
missing permissions, `/rest/v1/license` from 6.9, the purge import of an
empty `.nessus`, rollover scans at the maximum duration, and an optional mode
where every scan ends `Partial` with half its addresses scanned. It is for scratch
end-to-end runs only and is not in the connector image.

`connector_sync` also reports a catalog of the repositories, scan
repositories, policies and zones you allowed (ids and names), so OpenCTEM
can offer them; objects outside your allow-lists are never listed.

## A least-privilege Tenable.sc user

Create a dedicated Tenable.sc user for OpenCTEM. Give it a role that can only
view vulnerability data, and only for the repositories you list in
`allow.repositories`. Do not give it administrator rights. For scan launch,
add only the right to create scans, share with it only the policies in
`scan_policies`, and give it the repositories in `scan_repositories` and the
zones in `scan_zones`; without scan launch, give it no scan rights. Generate its API keys (Tenable.sc 5.13 or later, with API key
authentication enabled under System Configuration) and store them in the key
files, owned by root and readable only by the connector's user.

For rotation: with aging or purge the same user needs group access to the
rotation repository (purge also uploads and imports a file into it). Recycle
needs a second key pair from a Tenable.sc **Administrator**, used only to
read, create and delete the two rotation repositories (administrators manage
repositories but cannot read vulnerability data, so the split is required).
Error answers for rejected keys and missing permissions are HTTP 400 on
Tenable.sc; the connector reports them as rejected keys or forbidden.

Every query names one repository in the documented filter form
(`{"id": N}`), and every row whose repository is not the queried one is
dropped and counted (`skipped.other_repository`): the API reference says
filter operators are not validated, so the connector never relies on the
filter alone.

## What is sent to OpenCTEM

- Reports are CTIS 2.0 documents (media type `application/vnd.ctis+json;
  version=2.0`) with `metadata.channel` `integration`, the tool `tenable_sc`
  and the technique `va`. A document never carries a platform id: the report
  id is a producer UUIDv7 stamped by the client, and the binding to the
  command stays in the transport. Tenable's own names travel as
  `source_refs` with system `tenable_sc`: `instance:<name>` and
  `scan_result:<id>` on the document, `host:<uuid>` on an asset, and
  `plugin:<id>` and `vuln:<uuid>` on a finding.
- Hosts as assets with canonical values: a `host` named by its DNS name (with
  an `ip_address` asset for its address and a `resolves_to` relationship), or
  an `ip_address` when Tenable.sc has no DNS name. NetBIOS name and MAC
  addresses are identity hints and identifiers, the OS is a technology, the
  repository, ACR and AES stay in the asset's opaque `properties`.
- A finding on a port belongs to a `service` asset (`host:port/transport`,
  for tcp, udp and sctp) that its host `exposes`; a finding without a port (or
  with another protocol) belongs to the host. Every report carries the host
  and service assets of its findings.
- Vulnerabilities as findings: rule (plugin) id and name, severity, all CVEs
  in `vulnerability.ids`, `scores[]` (CVSS v3, else v2, and v4, each with its
  version and vector; VPR as a `vendor` score labelled `vpr`; EPSS), a
  `public_exploit` threat signal when an exploit is available, the plugin
  family, publication and patch dates (the patch date is
  `remediation.patch_published_at` and marks the fix available), first and
  last seen, the port as the network location, the plugin output as a
  `raw_text` evidence item (at most 64 KiB), accept-risk as a suppression, the
  last mitigation as `source_lifecycle.last_fixed_at`, and the open or
  mitigated state. Mitigated rows carry the status `resolved`; the platform
  decides what to do with them.
- On completion: counts, the Tenable.sc version and the licensed and active
  IP counts. Never the URL or the keys.

Every Tenable.sc response is treated as untrusted: size caps, per-field
caps, control and bidi characters removed, only `http`/`https` references,
scores and dates outside their ranges dropped. A malformed response or a
query with more records than `max_records` fails the sync before anything
from that query is pushed.
