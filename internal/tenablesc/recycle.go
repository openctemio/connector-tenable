package tenablesc

// Licence rotation by recycling (opt-in, operation recycle). Tenable.sc has
// no API that removes selected hosts from a repository; deleting a
// repository removes its data and the licence count updates (Security
// Center user guide, "Reclaiming Licenses"). The sensor owner names two
// rotation repositories; at most one holds data. After the platform
// confirmed the previous batch's results were ingested, a batch:
//
//  1. reads the current repository's definition (typeFields: ipRange and
//     lifetimes; organizations with groupAssign) with the administrator
//     keys;
//  2. creates the other name from it as a universal repository (since 6.8
//     a new Local repository may only be mobile or universal);
//  3. reads the replacement back and checks it: universal, the same IP
//     range and lifetimes, the same organizations and group access, a
//     range that covers the batch, and visible to the scanning user;
//  4. only then deletes the old repository.
//
// Any failure stops the batch with the reason before anything is deleted.
// When both repositories exist (an earlier recycle stopped after the
// create), the newer one is the replacement: it is checked again and the
// older one deleted only when it passes. The administrator keys are used
// for nothing else.

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
)

// repositoryFields are read from a rotation repository. ipRange, the
// lifetimes and trendingDays come inside typeFields; organizations (with
// groupAssign) only for an administrator session (API reference,
// Repository).
const repositoryFields = "id,uuid,name,description,type,dataFormat,createdTime,typeFields,organizations"

// repositoryDef is a repository definition as /rest/repository returns it.
type repositoryDef struct {
	ID            flexString     `json:"id"`
	UUID          string         `json:"uuid"`
	Name          string         `json:"name"`
	Description   string         `json:"description"`
	Type          string         `json:"type"`
	DataFormat    string         `json:"dataFormat"`
	CreatedTime   flexInt        `json:"createdTime"`
	TypeFields    repoTypeFields `json:"typeFields"`
	Organizations []repoOrg      `json:"organizations"`
}

type repoTypeFields struct {
	IPRange                 string     `json:"ipRange"`
	TrendingDays            flexString `json:"trendingDays"`
	TrendWithRaw            flexString `json:"trendWithRaw"`
	ActiveVulnsLifetime     flexString `json:"activeVulnsLifetime"`
	PassiveVulnsLifetime    flexString `json:"passiveVulnsLifetime"`
	ComplianceVulnsLifetime flexString `json:"complianceVulnsLifetime"`
	MitigatedVulnsLifetime  flexString `json:"mitigatedVulnsLifetime"`
}

// lifetimes are the lifetime fields a replacement keeps (a universal
// repository has no lceVulnsLifetime).
func (t repoTypeFields) lifetimes() map[string]string {
	return map[string]string{
		"activeVulnsLifetime": string(t.ActiveVulnsLifetime), "passiveVulnsLifetime": string(t.PassiveVulnsLifetime),
		"complianceVulnsLifetime": string(t.ComplianceVulnsLifetime), "mitigatedVulnsLifetime": string(t.MitigatedVulnsLifetime),
	}
}

type repoOrg struct {
	ID          flexString `json:"id"`
	Name        string     `json:"name"`
	GroupAssign string     `json:"groupAssign"`
}

func (d *repositoryDef) id() string { return numericID(string(d.ID)) }

// RepositoriesNamed returns the Local repositories whose name is one of
// names, with their definitions. A name used twice is an error.
func (c *Client) RepositoriesNamed(ctx context.Context, names ...string) ([]repositoryDef, error) {
	var list []repositoryDef
	if err := c.do(ctx, http.MethodGet, "/repository", url.Values{"fields": {repositoryFields}}, nil, 0, &list); err != nil {
		return nil, err
	}
	var out []repositoryDef
	seen := map[string]bool{}
	for _, d := range list {
		if !slices.Contains(names, d.Name) {
			continue
		}
		if seen[d.Name] {
			return nil, fmt.Errorf("more than one repository is named %q", d.Name)
		}
		seen[d.Name] = true
		if !strings.EqualFold(d.Type, "Local") || d.id() == "" {
			return nil, fmt.Errorf("repository %q is not a local repository with an id", d.Name)
		}
		out = append(out, d)
	}
	return out, nil
}

// Repository reads repository id's definition.
func (c *Client) Repository(ctx context.Context, id string) (*repositoryDef, error) {
	if numericID(id) == "" {
		return nil, errors.New("tenable.sc: not a repository id")
	}
	var d repositoryDef
	if err := c.do(ctx, http.MethodGet, "/repository/"+id, url.Values{"fields": {repositoryFields}}, nil, 0, &d); err != nil {
		return nil, err
	}
	return &d, nil
}

// DeleteRepository deletes repository id and its data.
func (c *Client) DeleteRepository(ctx context.Context, id string) error {
	if numericID(id) == "" {
		return errors.New("tenable.sc: not a repository id")
	}
	return c.do(ctx, http.MethodDelete, "/repository/"+id, nil, nil, 0, nil)
}

// CreateReplacement creates repository name as a universal Local
// repository with src's description, IP range, lifetimes and organization
// access, and returns its id. trendingDays and trendWithRaw are sent only
// before 6.9, where trending moved out of the repository.
func (c *Client) CreateReplacement(ctx context.Context, src *repositoryDef, name, version string) (string, error) {
	body := map[string]any{"name": name, "description": src.Description, "type": "Local", "dataFormat": "universal",
		"ipRange": src.TypeFields.IPRange}
	for k, v := range src.TypeFields.lifetimes() {
		if v != "" {
			body[k] = v
		}
	}
	if !versionAtLeast(version, 6, 9) {
		if v := string(src.TypeFields.TrendingDays); v != "" {
			body["trendingDays"] = v
		}
		if v := string(src.TypeFields.TrendWithRaw); v != "" {
			body["trendWithRaw"] = v
		}
	}
	orgs := make([]map[string]string, 0, len(src.Organizations))
	for _, o := range src.Organizations {
		if id := numericID(string(o.ID)); id != "" {
			orgs = append(orgs, map[string]string{"id": id, "groupAssign": o.GroupAssign})
		}
	}
	body["organizations"] = orgs
	var r struct {
		ID flexString `json:"id"`
	}
	if err := c.do(ctx, http.MethodPost, "/repository", nil, body, 0, &r); err != nil {
		return "", err
	}
	id := numericID(string(r.ID))
	if id == "" {
		return "", errors.New("tenable.sc created a repository without a usable id")
	}
	return id, nil
}

// adminInstance is in with the recycle administrator keys: the client for
// repository changes only.
func adminInstance(in *Instance) *Instance {
	cp := *in
	cp.AccessKey, cp.SecretKey = in.Recycle.AdminAccessKey, in.Recycle.AdminSecretKey
	return &cp
}

// rotationState is the rotation repositories found by name: current is the
// one batches scan into (the newer when both exist), older the one an
// unfinished recycle left behind.
type rotationState struct {
	admin   *Client
	current *repositoryDef
	older   *repositoryDef
}

// ids are the rotation repositories' ids (a resumed result may be in any).
func (s *rotationState) ids() []string {
	out := []string{s.current.id()}
	if s.older != nil {
		out = append(out, s.older.id())
	}
	return out
}

// rotationRefusal marks a rotation failure as "nothing was scanned": the
// platform retries instead of stalling, and the cause stays matchable.
func rotationRefusal(name string, err error) error {
	return fmt.Errorf("%w: rotation repository %q: %w", ErrRefused, name, err)
}

// resolveRecycle finds the recycle rotation repositories by the configured
// names; a payload never names them.
func (r *scanRun) resolveRecycle() (*rotationState, error) {
	rc := r.job.inst.Recycle
	newClient := r.e.newClient
	if newClient == nil {
		newClient = NewClient
	}
	admin, err := newClient(adminInstance(r.job.inst))
	if err != nil {
		return nil, err
	}
	found, err := admin.RepositoriesNamed(r.ctx, rc.RepositoryNames[0], rc.RepositoryNames[1])
	if err != nil {
		return nil, rotationRefusal(rc.RepositoryNames[0], err)
	}
	switch len(found) {
	case 0:
		return nil, rotationRefusal(rc.RepositoryNames[0], fmt.Errorf("neither %q nor %q exists: the Tenable.sc administrator creates the first one", rc.RepositoryNames[0], rc.RepositoryNames[1]))
	case 1:
		return &rotationState{admin: admin, current: &found[0]}, nil
	}
	// Both exist: the newer is the replacement an earlier recycle created.
	slices.SortFunc(found, func(a, b repositoryDef) int {
		if c := cmp.Compare(a.CreatedTime, b.CreatedTime); c != 0 {
			return c
		}
		ai, _ := strconv.ParseInt(a.id(), 10, 64)
		bi, _ := strconv.ParseInt(b.id(), 10, 64)
		return cmp.Compare(ai, bi)
	})
	return &rotationState{admin: admin, current: &found[1], older: &found[0]}, nil
}

// otherName is the recycle name that is not name.
func (r *scanRun) otherName(name string) string {
	n := r.job.inst.Recycle.RepositoryNames
	if n[0] == name {
		return n[1]
	}
	return n[0]
}

// prepareRecycle returns the repository the batch scans into, recycling
// first when the batch asks for it.
func (r *scanRun) prepareRecycle(rs *rotationState) (string, error) {
	cur := rs.current
	switch {
	case !r.job.recycle && rs.older == nil:
		if err := r.verifyRepository(cur, nil); err != nil {
			return "", rotationRefusal(cur.Name, err)
		}
		return cur.id(), nil
	case !r.job.recycle:
		// An earlier recycle created the newer one and stopped: scan into
		// it when it passes the checks; the older one is deleted by the
		// next recycle.
		if err := r.verifyRepository(cur, rs.older); err != nil {
			return "", rotationRefusal(cur.Name, fmt.Errorf("an earlier recycle left two repositories and the newer one fails the checks: %w", err))
		}
		return cur.id(), nil
	case rs.older != nil:
		// Finish the earlier recycle: check the replacement, then delete
		// the old repository.
		if err := r.verifyRepository(cur, rs.older); err != nil {
			return "", rotationRefusal(cur.Name, fmt.Errorf("replacement fails the checks, nothing was deleted: %w", err))
		}
		if err := r.deleteOld(rs.admin, rs.older); err != nil {
			return "", err
		}
		return cur.id(), nil
	}
	// A new recycle: create the other repository from the current one.
	if err := r.verifySource(cur); err != nil {
		return "", rotationRefusal(cur.Name, fmt.Errorf("cannot recycle, nothing was created or deleted: %w", err))
	}
	name := r.otherName(cur.Name)
	newID, err := rs.admin.CreateReplacement(r.ctx, cur, name, r.version)
	if err != nil {
		return "", rotationRefusal(name, fmt.Errorf("create the replacement, nothing was deleted: %w", err))
	}
	repl, err := rs.admin.Repository(r.ctx, newID)
	if err != nil {
		return "", rotationRefusal(name, fmt.Errorf("read the replacement back, nothing was deleted: %w", err))
	}
	if err := r.verifyRepository(repl, cur); err != nil {
		return "", rotationRefusal(name, fmt.Errorf("replacement %s fails the checks, nothing was deleted: %w", newID, err))
	}
	if err := r.deleteOld(rs.admin, cur); err != nil {
		return "", err
	}
	r.e.logf("tenable.sc %s: rotation repository recycled (%q %s -> %q %s)", r.job.inst.Name, cur.Name, cur.id(), name, newID)
	return newID, nil
}

// deleteOld deletes the repository a verified replacement took over from,
// then forgets the licence numbers so the guard reads them again.
func (r *scanRun) deleteOld(admin *Client, old *repositoryDef) error {
	if err := admin.DeleteRepository(r.ctx, old.id()); err != nil {
		return rotationRefusal(old.Name, fmt.Errorf("the replacement is verified but the old repository could not be deleted (the next recycle deletes it): %w", err))
	}
	r.recycledFrom = old.id()
	r.license = nil
	return nil
}

// verifySource checks that a repository can be copied: an IP range and
// organizations (an administrator session lists them).
func (r *scanRun) verifySource(src *repositoryDef) error {
	if strings.TrimSpace(src.TypeFields.IPRange) == "" {
		return errors.New("it has no IP range (typeFields.ipRange)")
	}
	if len(src.Organizations) == 0 {
		return errors.New("it lists no organizations: are the recycle keys an administrator's?")
	}
	return nil
}

// verifyRepository checks the repository a batch scans into: Local, an IP
// range that covers the batch's address targets, visible to the scanning
// user; and, for a replacement of src, universal with src's IP range,
// lifetimes and organization access.
func (r *scanRun) verifyRepository(d, src *repositoryDef) error {
	if !strings.EqualFold(d.Type, "Local") {
		return fmt.Errorf("type %q is not Local", d.Type)
	}
	ranges, err := parseIPRange(d.TypeFields.IPRange)
	if err != nil {
		return err
	}
	for _, t := range r.job.targets {
		if !rangesCover(ranges, t) {
			return fmt.Errorf("its IP range does not cover target %s", t)
		}
	}
	if src != nil {
		if !strings.EqualFold(d.DataFormat, "universal") {
			return fmt.Errorf("data format %q is not universal", d.DataFormat)
		}
		if normRange(d.TypeFields.IPRange) != normRange(src.TypeFields.IPRange) {
			return fmt.Errorf("IP range %q differs from %q", sanitizeText(d.TypeFields.IPRange, 200), sanitizeText(src.TypeFields.IPRange, 200))
		}
		got := d.TypeFields.lifetimes()
		for k, v := range src.TypeFields.lifetimes() {
			if v != "" && got[k] != v {
				return fmt.Errorf("%s is %q, want %q", k, got[k], v)
			}
		}
		for _, o := range src.Organizations {
			i := slices.IndexFunc(d.Organizations, func(x repoOrg) bool { return numericID(string(x.ID)) == numericID(string(o.ID)) })
			if i < 0 {
				return fmt.Errorf("organization %s has no access", numericID(string(o.ID)))
			}
			if d.Organizations[i].GroupAssign != o.GroupAssign {
				return fmt.Errorf("organization %s group access is %q, want %q", numericID(string(o.ID)),
					sanitizeText(d.Organizations[i].GroupAssign, 32), sanitizeText(o.GroupAssign, 32))
			}
		}
	}
	visible, err := r.client.Repositories(r.ctx)
	if err != nil {
		return fmt.Errorf("list the scanning user's repositories: %w", err)
	}
	id, _ := strconv.Atoi(d.id())
	if !slices.ContainsFunc(visible, func(c CatalogItem) bool { return c.ID == id }) {
		return errors.New("the scanning user cannot see it (check the organization's group access)")
	}
	return nil
}

// ipSpan is one element of a repository IP range: first..last.
type ipSpan struct{ first, last netip.Addr }

// parseIPRange reads a repository ipRange: comma-separated addresses, CIDR
// ranges and first-last ranges. Empty or unreadable is an error (a scan
// into it would fail with "scan targets do not exist in the selected
// import repository").
func parseIPRange(s string) ([]ipSpan, error) {
	var out []ipSpan
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if p, err := netip.ParsePrefix(part); err == nil {
			p = p.Masked()
			out = append(out, ipSpan{p.Addr(), lastAddr(p)})
			continue
		}
		if a, err := netip.ParseAddr(part); err == nil {
			out = append(out, ipSpan{a.Unmap(), a.Unmap()})
			continue
		}
		if lo, hi, ok := strings.Cut(part, "-"); ok {
			a, err1 := netip.ParseAddr(strings.TrimSpace(lo))
			b, err2 := netip.ParseAddr(strings.TrimSpace(hi))
			if err1 == nil && err2 == nil && a.Unmap().BitLen() == b.Unmap().BitLen() && a.Unmap().Compare(b.Unmap()) <= 0 {
				out = append(out, ipSpan{a.Unmap(), b.Unmap()})
				continue
			}
		}
		return nil, fmt.Errorf("cannot read IP range element %q", sanitizeText(part, 64))
	}
	if len(out) == 0 {
		return nil, errors.New("it has no IP range (typeFields.ipRange)")
	}
	return out, nil
}

// normRange is an IP range in a canonical spelling for comparison.
func normRange(s string) string {
	parts := strings.Split(strings.ReplaceAll(s, " ", ""), ",")
	slices.Sort(parts)
	return strings.Join(parts, ",")
}

// rangesCover reports whether target (an address or CIDR; host names cannot
// be checked and pass) lies inside one span.
func rangesCover(spans []ipSpan, target string) bool {
	var first, last netip.Addr
	if p, err := netip.ParsePrefix(target); err == nil {
		p = p.Masked()
		first, last = p.Addr(), lastAddr(p)
	} else if a, err := netip.ParseAddr(target); err == nil {
		first, last = a.Unmap(), a.Unmap()
	} else {
		return true
	}
	for _, s := range spans {
		if s.first.BitLen() == first.BitLen() && s.first.Compare(first) <= 0 && last.Compare(s.last) <= 0 {
			return true
		}
	}
	return false
}

// lastAddr is the last address of p.
func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Masked().Addr().AsSlice()
	for i := p.Bits(); i < len(b)*8; i++ {
		b[i/8] |= 0x80 >> (i % 8)
	}
	a, _ := netip.AddrFromSlice(b)
	return a
}
