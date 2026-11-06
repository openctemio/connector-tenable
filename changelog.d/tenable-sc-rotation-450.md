### Security: rotation never deletes data before a verified replacement exists

- Recycle now uses two rotation repositories (`recycle.repository_names`, two names with the `openctem-` prefix). It reads the current one's definition from `typeFields` and `organizations[].groupAssign`, creates the other as a `universal` repository (6.8 allows only mobile or universal for new Local repositories), reads it back and checks the data format, IP range, lifetimes, group access, that the range covers the batch and that the scanning user can see it, and only then deletes the old one. Any failure stops the batch and deletes nothing. Before, a recycle on 6.8 or later could delete the repository and then fail to recreate it, and the recreated repository lost its IP range, lifetimes and group access.
- Upgrade: replace `recycle.repository_name` with `recycle.repository_names: [<existing name>, <second name>]`; the single-name form is refused at start.
- Every sync query names one repository in the documented filter form, and rows of any other repository are dropped and counted (`skipped.other_repository`), because Tenable.sc does not validate filter operators.

### Added: purge rotation mode (Beta, unverified)

- Operation `purge` with a `purge.repository_name` block: a batch may first remove the previous batch's addresses from that rotation repository by importing an empty `.nessus` whose `TARGET` lists exactly the hosts the previous batch imported, then confirms with an analysis query and the licence count that they are gone (`purge_unverified` otherwise). Refused for agent repositories and for hosts outside the previous batch. Needs no administrator key.

### Fixed

- An import `Blocked` by the licence fails with `IMPORT_BLOCKED` and `scan_result_id=<id>`; a later batch with `reimport_scan_result_id` imports that result again (`POST /rest/scanResult/{id}/import`) once the licence guard sees capacity.
- The licence guard refuses unless the licence status is `Valid` (Exceeded, Locked and Expired are refused with the status). On 6.9 and later it reads `/rest/v1/license` and falls back to `/rest/status`; results report `license_status` and `license_source`.
- `maxScanTime` is sent in whole hours (rounded up, at least 1), as the user guide names the setting; the connector's own stop still bounds the run. Rollover scans Tenable.sc creates at its maximum duration are deleted.
- HTTP 400 answers for rejected API keys or missing permissions are reported as rejected keys or forbidden (and stop a sync); a key database error is resubmitted.
- The mock (`scmock`) follows the documented shapes: `typeFields`, administrator-only `organizations`, the 6.8 create restriction, HTTP 400 for key and permission problems, `/rest/v1/license`, blocked re-import, purge import and rollover scans.
