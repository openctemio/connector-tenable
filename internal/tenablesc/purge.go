package tenablesc

// Licence rotation by purging (opt-in, operation purge; unverified against
// a real Tenable.sc). Tenable's knowledge base ("Remove IPs from
// repositories in Tenable Security Center") documents that importing a
// .nessus file with no host results whose TARGET preference lists
// addresses removes those addresses' data from the repository at once,
// which lowers the licence count. It does not work on agent repositories,
// and in a universal repository it removes every asset sharing the
// address; removed data cannot be recovered.
//
// So, after the platform confirmed the previous batch's results were
// ingested, a batch may purge the previous batch's addresses from the one
// rotation repository the sensor owner named:
//
//  1. find the previous batch's scan result (named after its command) in
//     that repository and read the hosts it imported;
//  2. refuse when any of them lies outside the previous batch's targets
//     the platform sent, or the repository is an agent repository;
//  3. build the empty .nessus with exactly those addresses as TARGET,
//     upload it and import it into the rotation repository;
//  4. check that the addresses are gone from the repository and that the
//     licence count dropped; otherwise fail with purge_unverified, so the
//     platform stalls rotation rather than over-using the licence.
//
// It needs only the organization user's upload and import rights.

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/netip"
	"net/textproto"
	"regexp"
	"slices"
	"strings"
)

// PurgeUnverifiedCode starts the error of a purge whose effect could not
// be confirmed; the platform stalls rotation on it.
const PurgeUnverifiedCode = "purge_unverified"

// ErrPurgeUnverified: the purge file was imported but the addresses are
// still in the repository or the licence count did not drop.
var ErrPurgeUnverified = errors.New(PurgeUnverifiedCode + ": the purge of the previous batch could not be confirmed")

// Purge limits.
const (
	maxPurgeAddresses = 65536
	purgeChecks       = 20
)

// PurgeRequest asks a batch to purge the previous batch's addresses first.
type PurgeRequest struct {
	// PreviousCommandID is the previous coverage batch's command; its scan
	// result is named after it.
	PreviousCommandID string `json:"previous_command_id"`
	// Targets are the previous batch's targets (addresses and CIDR ranges).
	Targets []string `json:"targets"`
}

type purgeJob struct {
	prevName string
	targets  []netip.Prefix
}

// admitPurge checks a purge request: a previous command id and address or
// CIDR targets only (the same rules as scan targets; no host names).
func admitPurge(p *PurgeRequest, a Allow) (*purgeJob, error) {
	id := sanitizeIdentifier(p.PreviousCommandID)
	if id == "" || id != p.PreviousCommandID {
		return nil, errors.New("purge.previous_command_id is not a command id")
	}
	if len(p.Targets) == 0 {
		return nil, errors.New("purge names no target")
	}
	if len(p.Targets) > a.MaxTargetsPerScan {
		return nil, fmt.Errorf("purge names %d targets, more than the %d allowed per scan", len(p.Targets), a.MaxTargetsPerScan)
	}
	j := &purgeJob{prevName: "openctem-" + id}
	for _, raw := range p.Targets {
		t, _, err := checkScanTarget(raw)
		if err != nil {
			return nil, fmt.Errorf("purge target %q: %v", sanitizeText(raw, 80), err)
		}
		pfx, err := netip.ParsePrefix(t)
		if err != nil {
			a, aerr := netip.ParseAddr(t)
			if aerr != nil {
				return nil, fmt.Errorf("purge target %q: only addresses and CIDR ranges can be purged", sanitizeText(raw, 80))
			}
			pfx = netip.PrefixFrom(a, a.BitLen())
		}
		j.targets = append(j.targets, pfx)
	}
	return j, nil
}

func (j *purgeJob) covers(a netip.Addr) bool {
	return slices.ContainsFunc(j.targets, func(p netip.Prefix) bool { return p.Contains(a) })
}

// resolvePurge finds the purge rotation repository by its configured name
// with the scanning user's keys and refuses an agent repository.
func (r *scanRun) resolvePurge() (*repositoryDef, error) {
	name := r.job.inst.Purge.RepositoryName
	found, err := r.client.RepositoriesNamed(r.ctx, name)
	if err != nil {
		return nil, rotationRefusal(name, err)
	}
	if len(found) == 0 {
		return nil, rotationRefusal(name, errors.New("no repository has this name, or the scanning user cannot see it"))
	}
	d := &found[0]
	if strings.EqualFold(d.DataFormat, "agent") {
		return nil, rotationRefusal(name, errors.New("it is an agent repository, which a purge import cannot clear"))
	}
	return d, nil
}

// purgePrevious removes the previous batch's addresses from repo.
func (r *scanRun) purgePrevious(repo *repositoryDef) error {
	pj := r.job.purge
	repoID := repo.id()
	results, err := r.client.FindScanResults(r.ctx, pj.prevName)
	if err != nil {
		return rotationRefusal(repo.Name, fmt.Errorf("find the previous batch's scan result: %w", err))
	}
	var prev *OwnScan
	for i := range results {
		if results[i].RepositoryID == repoID {
			prev = &results[i]
			break
		}
	}
	if prev == nil {
		return rotationRefusal(repo.Name, fmt.Errorf("the previous batch's scan result %q is not in the rotation repository", pj.prevName))
	}
	if strings.EqualFold(prev.ImportStatus, "No Results") {
		return nil // nothing was imported, nothing to purge
	}
	if !goodImportStatuses[strings.ToLower(prev.ImportStatus)] {
		return rotationRefusal(repo.Name, fmt.Errorf("the previous batch's scan result %s has import status %q", prev.ID, prev.ImportStatus))
	}
	hosts, err := r.hostAddresses(Query{Tool: "sumip", DataSource: "individual", ScanID: prev.ID, View: "all",
		Filters: []Filter{}, SortField: "ip", SortDir: sortDir}, repoID)
	if err != nil {
		return rotationRefusal(repo.Name, fmt.Errorf("read the previous batch's hosts: %w", err))
	}
	for _, a := range hosts {
		if !pj.covers(a) {
			return rotationRefusal(repo.Name, fmt.Errorf("host %s of the previous scan result is outside the previous batch's targets; nothing was purged", a))
		}
	}
	if len(hosts) == 0 {
		return nil
	}
	ips := make([]string, 0, len(hosts))
	for _, a := range hosts {
		ips = append(ips, a.String())
	}
	present, err := r.repoHosts(repoID, ips)
	if err != nil {
		return rotationRefusal(repo.Name, fmt.Errorf("read the rotation repository: %w", err))
	}
	if len(present) == 0 {
		return nil // already aged out or purged
	}
	before, err := r.client.LicenseState(r.ctx, r.version)
	if err != nil {
		return rotationRefusal(repo.Name, fmt.Errorf("licence before the purge: %w", err))
	}
	file, err := purgeFile("openctem-purge-"+sanitizeIdentifier(r.cmdID), present)
	if err != nil {
		return rotationRefusal(repo.Name, err)
	}
	name, err := r.client.UploadFile(r.ctx, "openctem-purge.nessus", file)
	if err != nil {
		return rotationRefusal(repo.Name, fmt.Errorf("upload the purge file: %w", err))
	}
	if err := r.client.ImportFile(r.ctx, name, repoID); err != nil {
		// Whether a failed import removed anything is unknown.
		return fmt.Errorf("%w: import of the purge file into %q failed: %v", ErrPurgeUnverified, repo.Name, err)
	}
	r.license = nil
	for i := 0; ; i++ {
		left, err := r.repoHosts(repoID, present)
		var after License
		if err == nil {
			after, err = r.client.LicenseState(r.ctx, r.version)
		}
		if err == nil && len(left) == 0 && after.ActiveIPs < before.ActiveIPs {
			r.purged = len(present)
			r.license = &after
			r.e.logf("tenable.sc %s: purged %d address(es) of the previous batch from %q (active %d -> %d)",
				r.job.inst.Name, len(present), repo.Name, before.ActiveIPs, after.ActiveIPs)
			return nil
		}
		if i+1 >= purgeChecks {
			why := fmt.Sprintf("%d of %d address(es) still in %q, active %d -> %d", len(left), len(present), repo.Name, before.ActiveIPs, after.ActiveIPs)
			if err != nil {
				why = err.Error()
			}
			return fmt.Errorf("%w (%s)", ErrPurgeUnverified, why)
		}
		if err := r.e.wait(r.ctx, r.e.interval()); err != nil {
			return err
		}
	}
}

// repoHosts returns which of ips the repository holds (cumulative sumip
// with the repository and ip filters; rows of another repository are not
// counted).
func (r *scanRun) repoHosts(repoID string, ips []string) ([]string, error) {
	got, err := r.hostAddresses(Query{Tool: "sumip", DataSource: "cumulative", SortField: "ip", SortDir: sortDir, Filters: []Filter{
		{FilterName: "repository", Operator: "=", Value: map[string]string{"id": repoID}},
		{FilterName: "ip", Operator: "=", Value: strings.Join(ips, ",")},
	}}, repoID)
	if err != nil {
		return nil, err
	}
	want := map[string]bool{}
	for _, ip := range ips {
		want[ip] = true
	}
	var out []string
	for _, a := range got {
		if want[a.String()] {
			out = append(out, a.String())
		}
	}
	return out, nil
}

// hostAddresses pages a sumip query and returns the addresses of the rows
// in repository repoID.
func (r *scanRun) hostAddresses(q Query, repoID string) ([]netip.Addr, error) {
	size := r.job.inst.Limits.PageSize
	seen := map[netip.Addr]bool{}
	var out []netip.Addr
	for offset := 0; ; {
		p, err := r.client.Analysis(r.ctx, q, offset, size)
		if err != nil {
			return nil, err
		}
		for _, raw := range p.Results {
			var row vulnRow
			if err := json.Unmarshal(raw, &row); err != nil {
				return nil, fmt.Errorf("tenable.sc returned an unreadable host row: %w", err)
			}
			if numericID(string(row.Repository.ID)) != repoID {
				continue
			}
			a, err := netip.ParseAddr(strings.TrimSpace(row.IP))
			if err != nil || seen[a.Unmap()] {
				continue
			}
			seen[a.Unmap()] = true
			out = append(out, a.Unmap())
			if len(out) > maxPurgeAddresses {
				return nil, fmt.Errorf("more than %d hosts", maxPurgeAddresses)
			}
		}
		offset += len(p.Results)
		if len(p.Results) == 0 || offset >= p.Total {
			return out, nil
		}
	}
}

var purgeReportNameRE = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

// purgeFile builds the purge .nessus (Nessus v2): a policy whose TARGET
// preference lists exactly ips, and a report with no host. Every entry must
// be one IP address or CIDR range outside the blocked ranges; nothing else
// is ever written, and the text is XML-escaped anyway.
func purgeFile(reportName string, ips []string) ([]byte, error) {
	if !purgeReportNameRE.MatchString(reportName) {
		return nil, errors.New("purge file: invalid report name")
	}
	if len(ips) == 0 || len(ips) > maxPurgeAddresses {
		return nil, fmt.Errorf("purge file: %d addresses (1..%d)", len(ips), maxPurgeAddresses)
	}
	seen := map[string]bool{}
	clean := make([]string, 0, len(ips))
	for _, ip := range ips {
		t, _, err := checkScanTarget(ip)
		if err != nil || t != ip {
			return nil, fmt.Errorf("purge file: %q is not one address or CIDR range", sanitizeText(ip, 64))
		}
		if _, perr := netip.ParsePrefix(t); perr != nil {
			if _, aerr := netip.ParseAddr(t); aerr != nil {
				return nil, fmt.Errorf("purge file: %q is not one address or CIDR range", sanitizeText(ip, 64))
			}
		}
		if !seen[t] {
			seen[t] = true
			clean = append(clean, t)
		}
	}
	var b bytes.Buffer
	esc := func(s string) { _ = xml.EscapeText(&b, []byte(s)) }
	b.WriteString(`<?xml version="1.0" ?>` + "\n<NessusClientData_v2>\n<Policy>\n<policyName>")
	esc(reportName)
	b.WriteString("</policyName>\n<Preferences>\n<ServerPreferences>\n<preference><name>TARGET</name><value>")
	esc(strings.Join(clean, ","))
	b.WriteString("</value></preference>\n</ServerPreferences>\n<PluginsPreferences></PluginsPreferences>\n</Preferences>\n" +
		"<FamilySelection></FamilySelection>\n<IndividualPluginSelection></IndividualPluginSelection>\n</Policy>\n<Report name=\"")
	esc(reportName)
	b.WriteString("\" xmlns:cm=\"http://www.nessus.org/cm\">\n</Report>\n</NessusClientData_v2>\n")
	return b.Bytes(), nil
}

// UploadFile uploads content (POST /rest/file/upload, multipart field
// Filedata) and returns the server-side file name.
func (c *Client) UploadFile(ctx context.Context, name string, content []byte) (string, error) {
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	h := make(textproto.MIMEHeader)
	h.Set("Content-Disposition", fmt.Sprintf(`form-data; name="Filedata"; filename=%q`, name))
	h.Set("Content-Type", "application/octet-stream")
	part, err := mw.CreatePart(h)
	if err != nil {
		return "", err
	}
	if _, err := part.Write(content); err != nil {
		return "", err
	}
	if err := mw.Close(); err != nil {
		return "", err
	}
	var r struct {
		Filename string `json:"filename"`
	}
	if err := c.doRaw(ctx, http.MethodPost, "/file/upload", nil, body.Bytes(), mw.FormDataContentType(), 0, &r); err != nil {
		return "", err
	}
	if !purgeReportNameRE.MatchString(r.Filename) {
		return "", errors.New("tenable.sc returned no usable uploaded file name")
	}
	return r.Filename, nil
}

// ImportFile imports an uploaded result file into repository repoID
// (POST /rest/scanResult/import). The API documents no import field for
// "remove vulnerabilities from hosts that do not reply", so none is sent.
func (c *Client) ImportFile(ctx context.Context, filename, repoID string) error {
	if numericID(repoID) == "" {
		return errors.New("tenable.sc: not a repository id")
	}
	body := map[string]any{"filename": filename, "repository": map[string]string{"id": repoID},
		"classifyMitigatedAge": "0", "dhcpTracking": "false", "scanningVirtualHosts": "false"}
	return c.do(ctx, http.MethodPost, "/scanResult/import", nil, body, 0, nil)
}

// ReimportScanResult imports scan result id again (POST
// /rest/scanResult/{id}/import), for a result whose import was Blocked.
func (c *Client) ReimportScanResult(ctx context.Context, id string) error {
	if numericID(id) == "" {
		return errors.New("tenable.sc: not a scan result id")
	}
	return c.do(ctx, http.MethodPost, "/scanResult/"+id+"/import", nil,
		map[string]any{"classifyMitigatedAge": "0", "dhcpTracking": "false", "scanningVirtualHosts": "false"}, 0, nil)
}
