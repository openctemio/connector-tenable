### Fixed: no tool-sandbox failure on the connector's health checks

- The connector runs no tool process, so it no longer sets up the tool sandbox: its preflight reported "tool sandbox: launcher: this program does not call executor.RunLauncherIfRequested" as a failed check on the sensor's Setup & health page.
