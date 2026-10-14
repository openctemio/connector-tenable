// Command connector-tenable is the OpenCTEM Tenable Security Center
// (Tenable.sc) connector: a sensor that runs nothing but the connector. It
// pairs with the OpenCTEM platform like any sensor, takes connector_sync and
// connector_scan commands, talks to the Tenable.sc instances its owner
// configured, and pushes the results as CTIS reports. The Tenable.sc API keys
// stay in this process; it runs no scanner and parses no scanned target's
// content, so a hostile scan result never shares a process with the keys.
//
// Platform connection, pairing, identity, heartbeat, local policy, outbox and
// shutdown come from the sensor SDK (sdk-go pkg/sensorkit) and its SENSOR_*
// settings; the connector reads its own config (-config, TENABLE_SC_CONFIG,
// the TENABLE_SC_* shorthand or /etc/openctem/connectors/tenable-sc.yaml).
//
// Design: https://github.com/openctemio/openctem/blob/develop/api/docs/rfcs/RFC-047-tenable-sc-sensor-connector.md
package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/sensorkit"

	"github.com/openctemio/connector-tenable/internal/tenablesc"
)

// Version is set at build time: -ldflags "-X main.Version=v1.2.3".
var Version = "dev"

// Capability is the platform capability the connector provides (ctis
// capability taxonomy): a network vulnerability assessment through a
// connected scanner product.
const Capability = "network_va.connector"

func main() {
	configPath := flag.String("config", "", "The Tenable.sc connector config the network owner wrote, read-only (or "+
		tenablesc.EnvConfig+" env, or the TENABLE_SC_* env shorthand; default "+tenablesc.DefaultConfigPath+" when it exists)")
	showVersion := flag.Bool("version", false, "Print the version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println("connector-tenable", Version)
		return
	}

	cfg, warns, err := tenablesc.Load(tenablesc.LoadOptions{Path: *configPath})
	for _, w := range warns {
		fmt.Fprintln(os.Stderr, "Warning:", w)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(sensorkit.ExitUsage)
	}
	if cfg == nil {
		fmt.Fprintln(os.Stderr, "Error: no Tenable.sc instance is configured: write "+tenablesc.DefaultConfigPath+
			" (or pass -config, or set "+tenablesc.EnvConfig+" or the TENABLE_SC_* shorthand)")
		os.Exit(sensorkit.ExitUsage)
	}

	kit, err := sensorkit.New(sensorkit.Options{
		Name: "connector-tenable", Version: Version, ProductName: "openctemio-connector-tenable",
		// The connector runs no tool process: the tool sandbox has nothing
		// to confine (the connector's own process is confined by its
		// container: non-root, read-only, no capabilities).
		Sandbox: "off",
	})
	sensorkit.Exit(err)

	// connector_sync pulls from the configured instances; connector_scan
	// launches one scan, only where the owner allowed scans, re-checking
	// every target against the local policy in force at each scan.
	kit.HandleCommand(tenablesc.CommandTypeSync, tenablesc.NewSyncExecutor(cfg, kit.Client()))
	if cfg.AllowsScans() {
		kit.HandleCommand(tenablesc.CommandTypeScan, tenablesc.NewScanExecutor(cfg, kit.Client(), localPolicy{current: kit.LocalPolicy}))
	}
	if err := kit.Tools().Register(core.ToolSpec{
		Name: tenablesc.ToolName, Kind: core.ToolKindCollector, Version: Version,
		Capabilities: []string{Capability},
	}); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(sensorkit.ExitUsage)
	}
	sensorkit.Exit(kit.Run(context.Background()))
}

// localPolicy is the kit's local policy in force now (a SIGHUP reload
// replaces it), asked at each check.
type localPolicy struct {
	current func() *core.LocalPolicy
}

func (p localPolicy) CheckTarget(ctx context.Context, target string) error {
	return p.current().CheckTarget(ctx, target)
}
