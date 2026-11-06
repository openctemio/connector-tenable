package tenablesc

import (
	"context"
	"errors"
	"net/http"
	"strings"
)

// LicenseState reads the IP licence. On 6.9 and later it reads
// GET /rest/v1/license first (status, blades.sc.limit, blades.sc.used):
// Tenable deprecated the licence fields of /rest/system in 6.9.0 and points
// clients to /v1/license. /rest/status still documents licenseStatus,
// licensedIPs and activeIPs, so it is the fallback (and the only source
// before 6.9) when /v1/license fails or lacks the numbers. Rejected keys
// and a cancelled context are returned, never hidden by the fallback.
func (c *Client) LicenseState(ctx context.Context, version string) (License, error) {
	if versionAtLeast(version, 6, 9) {
		l, err := c.licenseV1(ctx)
		switch {
		case err == nil && l.LicensedIPs > 0 && l.Status != "":
			return l, nil
		case err != nil && (errors.Is(err, ErrCredentialsRejected) || ctx.Err() != nil):
			return License{}, err
		}
	}
	return c.Status(ctx)
}

func (c *Client) licenseV1(ctx context.Context) (License, error) {
	var r struct {
		Status string `json:"status"`
		Blades struct {
			SC struct {
				Limit  flexInt `json:"limit"`
				Used   flexInt `json:"used"`
				Status string  `json:"status"`
			} `json:"sc"`
		} `json:"blades"`
	}
	if err := c.do(ctx, http.MethodGet, "/v1/license", nil, nil, 0, &r); err != nil {
		return License{}, err
	}
	status := r.Status
	// The Security Center blade's own status wins when it is worse.
	if b := r.Blades.SC.Status; b != "" && !strings.EqualFold(b, "Valid") {
		status = b
	}
	l := License{Status: sanitizeText(status, 32), Source: "v1/license"}
	if r.Blades.SC.Limit > 0 {
		l.LicensedIPs = int64(r.Blades.SC.Limit)
	}
	if r.Blades.SC.Used > 0 {
		l.ActiveIPs = int64(r.Blades.SC.Used)
	}
	return l, nil
}

// licenseValid reports whether a licence status lets the guard use the
// numbers: only Valid. Exceeded (functionality progressively reduced),
// Locked and Expired are refused (Security Center user guide, "License
// Statuses"), and so is a missing status.
func licenseValid(status string) bool { return strings.EqualFold(strings.TrimSpace(status), "Valid") }
