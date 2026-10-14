### Added: the Tenable.sc connector as its own image

- The Tenable Security Center connector moved out of the OpenCTEM sensor into this repository and the image `ghcr.io/openctemio/connector-tenable`: a sensor that runs nothing but the connector, so the Tenable.sc API keys never share a process or a container with scanners that parse scanned content. It pairs with OpenCTEM like any sensor, reports the tool `tenable_sc` with the capability `network_va.connector`, and serves `connector_sync` (pull) and `connector_scan` (launch, track, pull, clean up).
- Config: `-config`, `TENABLE_SC_CONFIG`, the `TENABLE_SC_*` shorthand or `/etc/openctem/connectors/tenable-sc.yaml`, with the same keys and allow-lists as the sensor's connector. Platform connection and policy settings are the sensor's (`SENSOR_*`).
- A scan reports liveness and per-target outcomes, a refused import fails with the reason, a restart follows the scan it already launched, and the platform's run and host keys in the payload are accepted.
- `cmd/tenablesc-mock`: a Tenable.sc API mock for tests and scratch end-to-end runs (not in the image).
