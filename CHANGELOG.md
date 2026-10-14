# Changelog

All notable changes to the OpenCTEM Tenable.sc connector are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
the project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

A release is a `vX.Y.Z` tag on `main`, created by the Release Tag workflow
from a merged release PR: `release.yml` publishes signed binaries
(GoReleaser) and `images.yml` the signed multi-arch image
`ghcr.io/openctemio/connector-tenable`.

Unreleased changes are kept one file per change in
[`changelog.d/`](changelog.d/README.md) and folded in here by the release
(Release Prepare).

## [Unreleased]

## [v0.1.0] — 2026-10-14

### Added: the Tenable.sc connector as its own image

- The Tenable Security Center connector moved out of the OpenCTEM sensor into this repository and the image `ghcr.io/openctemio/connector-tenable`: a sensor that runs nothing but the connector, so the Tenable.sc API keys never share a process or a container with scanners that parse scanned content. It pairs with OpenCTEM like any sensor, reports the tool `tenable_sc` with the capability `network_va.connector`, and serves `connector_sync` (pull) and `connector_scan` (launch, track, pull, clean up).
- Config: `-config`, `TENABLE_SC_CONFIG`, the `TENABLE_SC_*` shorthand or `/etc/openctem/connectors/tenable-sc.yaml`, with the same keys and allow-lists as the sensor's connector. Platform connection and policy settings are the sensor's (`SENSOR_*`).
- A scan reports liveness and per-target outcomes, a refused import fails with the reason, a restart follows the scan it already launched, and the platform's run and host keys in the payload are accepted.
- `cmd/tenablesc-mock`: a Tenable.sc API mock for tests and scratch end-to-end runs (not in the image).

### Added: licence guard and opt-in rotation-repository recycling for Tenable.sc coverage

- A `connector_scan` may carry `licence_guard {new_addresses, headroom}`: the connector launches only when Tenable.sc has that free licence capacity (read from `/rest/status` at launch), and otherwise fails with `LICENCE_CAPACITY` before creating anything. After the import it reports the licence count again (`active_ips`, `active_ips_before`).
- New operation `recycle` with a `recycle` block (rotation repository name with the `openctem-` prefix, administrator key files): a batch with `rotation_repository` scans into that repository, and with `recycle_repository` deletes and recreates it first, which frees its licence count at once. Off unless the owner configures it; no other repository is ever touched. The repository fields sent on create are not yet verified against a real Tenable.sc.
- The Tenable.sc mock serves repository creation and can require administrator keys for repository changes.

### Fixed: no tool-sandbox failure on the connector's health checks

- The connector runs no tool process, so it no longer sets up the tool sandbox: its preflight reported "tool sandbox: launcher: this program does not call executor.RunLauncherIfRequested" as a failed check on the sensor's Setup & health page.
