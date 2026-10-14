# OpenCTEM Tenable.sc connector

Connects a **Tenable Security Center** (Tenable.sc) inside your network to
[OpenCTEM](https://github.com/openctemio/openctem). The connector:

- pulls hosts, open and mitigated vulnerabilities and plugin metadata
  (`connector_sync`);
- launches the scans OpenCTEM schedules, follows them, pulls their results
  and deletes the scan definition it created (`connector_scan`);
- pushes everything to OpenCTEM as CTIS reports.

It is a sensor of its own that runs nothing but the connector. **The
Tenable.sc API keys stay in this container.** OpenCTEM never receives, stores
or forwards them, and needs no route into your network: the connector opens
every connection, to OpenCTEM and to the Tenable.sc host you configure. It
runs no scanner and parses no scanned target's content, so hostile scan output
never shares a process with the keys.

In OpenCTEM it appears as a sensor that reports the tool `tenable_sc` with
the capability `network_va.connector`.

## Install

1. In OpenCTEM, **Settings → Sensors → Add sensor**: copy the pairing code.
2. Write the connector config (`tenable-sc.yaml`, see below) and the two key
   files of a least-privilege Tenable.sc user.
3. Run the connector next to your Tenable.sc:

   ```bash
   docker run -d --name connector-tenable --restart unless-stopped \
     --read-only --cap-drop ALL --security-opt no-new-privileges:true \
     -e SENSOR_API_URL=https://openctem.example.com \
     -e SENSOR_PAIRING_CODE=XXXX-XXXX \
     -v connector-tenable-data:/var/lib/openctem \
     -v /etc/openctem/connectors:/etc/openctem/connectors:ro \
     -v /run/secrets/tenable-sc:/run/secrets/tenable-sc:ro \
     ghcr.io/openctemio/connector-tenable:v0.1.0
   docker logs connector-tenable   # the pairing fingerprint to confirm in OpenCTEM
   ```

4. In OpenCTEM, approve the sensor and give it the grant the connector needs
   (job types `connector_sync`, and `connector_scan` if you allow scans; tool
   `tenable_sc`), then **Settings → Integrations → Tenable.sc**: pick this
   sensor and type the instance name from your config.

The image is distroless and runs as a non-root user (65532) under the default
seccomp profile; it needs no capability, no privileged syscall and listens on
no port. Keep `/var/lib/openctem` on a volume: it holds the sensor identity
and the outbox of undelivered results.

## Configure

`/etc/openctem/connectors/tenable-sc.yaml` (or `-config`, or
`TENABLE_SC_CONFIG`), root-owned, mode 0640, mounted read-only:

```yaml
apiVersion: openctem.io/connector-tenable-sc/v1
instances:
  - name: sc-prod                      # the only thing OpenCTEM knows
    url: https://sc.corp.example        # https only
    ca_file: /etc/openctem/connectors/tenable-ca.pem
    access_key_file: /run/secrets/tenable-sc/access_key
    secret_key_file: /run/secrets/tenable-sc/secret_key
    allow:
      operations: [sync]               # add "scan" to allow scans
      repositories: [5, 7]             # nothing is read without it
      scan_policies: [1000003]         # required for scan
      scan_repositories: [5]           # required for scan
      max_targets_per_scan: 512
```

Every key, the allow-lists the platform can only narrow, TLS pinning, limits
and the least-privilege Tenable.sc role are in
[docs/tenable-sc.md](docs/tenable-sc.md). Platform connection, pairing and
local policy settings are the sensor SDK's `SENSOR_*` settings
(`SENSOR_API_URL`, `SENSOR_PAIRING_CODE`, `SENSOR_ALLOWED_RANGES`,
`SENSOR_LOCAL_POLICY`, …).

## Verify the image

```bash
cosign verify ghcr.io/openctemio/connector-tenable:v0.1.0 \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github\.com/openctemio/connector-tenable/\.github/workflows/images\.yml@refs/tags/v'
```

## Develop

```bash
go test -race ./...
go run ./cmd/tenablesc-mock -listen 192.0.2.10:8443 -estate estate.json -ca-out ca.pem
```

`cmd/tenablesc-mock` serves a Tenable.sc API mock built from the documented
shapes (scan and import status sequences, licence counting, blocked imports)
for tests and scratch end-to-end runs. It is not in the image.

Changes go through pull requests against `main`, each with one
`changelog.d/` fragment ([changelog.d/README.md](changelog.d/README.md)).
Releases: **Release Prepare** opens the release PR; merging it runs
**Release Tag**, which tags it and publishes the signed binaries and image.

Security reports: [SECURITY.md](SECURITY.md). License: [GPL-3.0](LICENSE).
