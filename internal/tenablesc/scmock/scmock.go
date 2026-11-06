// Package scmock is a small Tenable Security Center (Tenable.sc) REST API
// mock for tests and scratch end-to-end runs of the connector. It follows the
// shapes documented in the Tenable.sc API reference (Scan, Scan Result,
// Analysis, Repository, Status, System, Policy, Scan Zone, Plugin) and the
// licence rules of the Security Center user guide:
//
//   - every response is the documented envelope {type, response, error_code,
//     error_msg, warnings, timestamp}; numbers are sent as JSON strings, as
//     the product does;
//   - API keys are checked in the x-apikey header (accesskey=…; secretkey=…;);
//   - a launched scan result moves through Queued, Running and Completed, one
//     state per read, with totalIPs/completedIPs and totalChecks/
//     completedChecks counters; its import moves through Importing to
//     Finished, or to Blocked when importing it would exceed the IP licence;
//   - only hosts that reply (Alive) appear in a result; every scanned host
//     carries the scan-information plugin 19506 (severity info);
//   - the licence counts unique IPs across repositories that hold at least
//     one plugin outside the documented discovery-only list;
//   - deleting a repository removes its data and updates the count at once
//     (the documented way the count changes immediately);
//   - API key problems answer HTTP 400 (API key authorization guide): wrong
//     keys, and a user without the permission (repository management is
//     the administrator's; administrators read no analysis data);
//   - GET /repository returns ipRange and the lifetimes inside typeFields,
//     and organizations (with groupAssign) only to an administrator; a user
//     sees only repositories an organization grants group access to;
//   - from 6.8 a new Local repository may only be mobile or universal; a
//     scan whose targets are outside its repository's IP range is refused
//     (error 146);
//   - from 6.9 GET /rest/v1/license reports the licence (blades.sc);
//   - a Blocked result can be imported again (POST /scanResult/{id}/import);
//   - an uploaded .nessus with no host results, imported into a non-agent
//     repository, removes the addresses of its TARGET preference at once
//     (Tenable knowledge base, "Remove IPs from repositories");
//   - analysis filters it cannot read are ignored (the API reference says
//     filter operators are not validated), so a caller must check rows.
//
// It is not the product: nothing here is a statement about undocumented
// behaviour. It never listens on its own; callers serve Handler().
package scmock

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DiscoveryPlugins are plugin ids that do not make a host count against the
// licence (Security Center user guide, "License Requirements").
var DiscoveryPlugins = map[string]bool{
	"10180": true, "10287": true, "10335": true, "11219": true, "11933": true, "11936": true, "12053": true,
	"14272": true, "14274": true, "19506": true, "22964": true, "33812": true, "33813": true, "34220": true,
	"34277": true, "45590": true, "54615": true, "87413": true, "112154": true, "161455": true, "179042": true,
	"209654": true, "204872": true,
}

// Vuln is one plugin result on a host.
type Vuln struct {
	PluginID string  `json:"plugin_id"`
	Name     string  `json:"name"`
	Severity int     `json:"severity"` // 0 info .. 4 critical
	Port     int     `json:"port"`
	Protocol string  `json:"protocol"`
	CVE      string  `json:"cve,omitempty"` // comma-separated
	CVSSV3   float64 `json:"cvss_v3,omitempty"`
	Synopsis string  `json:"synopsis,omitempty"`
	Solution string  `json:"solution,omitempty"`
	Family   string  `json:"family,omitempty"`
}

// Host is one address of the simulated network.
type Host struct {
	IP      string `json:"ip"`
	DNSName string `json:"dns_name,omitempty"`
	NetBIOS string `json:"netbios_name,omitempty"`
	MAC     string `json:"mac,omitempty"`
	OS      string `json:"os,omitempty"`
	// Alive hosts reply to a scan; others are dead (absent from results).
	Alive bool   `json:"alive"`
	Vulns []Vuln `json:"vulns,omitempty"`
}

// Named is an id and a name (repositories, policies, zones).
type Named struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

// Options configure a mock.
type Options struct {
	AccessKey, SecretKey string
	// AdminAccessKey and AdminSecretKey, when set, are the only keys that
	// may create or delete repositories (an administrator's).
	AdminAccessKey, AdminSecretKey string
	Version                        string // default 6.4.0
	LicensedIPs                    int
	Hosts                          []Host
	Repositories                   []Named
	Policies                       []Named
	Zones                          []Named
	// RunningReads is how many reads of a running scan result pass before
	// it completes (default 2).
	RunningReads int
	// PartialScans makes every scan end "Partial" (finished, some results
	// available) with only the first half of its addresses scanned, as when
	// a scanner of the zone fails mid-scan.
	PartialScans bool
	// LicenseStatus is the licence status reported (default Valid).
	LicenseStatus string
	// RepositoryFormats and RepositoryRanges set a seeded repository's
	// dataFormat (default universal) and ipRange (default 10.0.0.0/8).
	RepositoryFormats map[int]string `json:"repository_formats,omitempty"`
	RepositoryRanges  map[int]string `json:"repository_ranges,omitempty"`
	// HiddenRepositories are seeded with groupAssign "" for the
	// organization: the user does not see them.
	HiddenRepositories []int `json:"hidden_repositories,omitempty"`
	// MaxTimeReached makes every scan reach its maximum duration: it ends
	// Partial and Tenable.sc creates a rollover scan for the rest.
	MaxTimeReached bool
}

// repo is a repository definition.
type repo struct {
	Named
	format    string
	ipRange   string
	lifetimes map[string]string
	trending  string
	group     string // groupAssign of organization 1
	created   int64
}

type scanDef struct {
	id, name, ipList string
	repo             int
	maxScanTime      string
	schedule         string
}

type scanResult struct {
	id, name     string
	repo         int
	targets      []string // addresses in the scan
	reads        int
	status       string
	importStatus string
	scanned      []string // addresses whose data the result holds
	checks       int
}

// Server is a running mock; safe for concurrent use.
type Server struct {
	mu      sync.Mutex
	o       Options
	hosts   map[string]*Host
	repos   map[int]*repo
	files   map[string][]byte
	data    map[int]map[string]bool // repository -> addresses with data
	scans   map[string]*scanDef
	results map[string]*scanResult
	next    int
	// Log, when set, receives one line per request (method, path, status).
	Log func(string)
}

// New returns a mock for o.
func New(o Options) *Server {
	if o.Version == "" {
		o.Version = "6.4.0"
	}
	if o.RunningReads <= 0 {
		o.RunningReads = 2
	}
	if o.LicenseStatus == "" {
		o.LicenseStatus = "Valid"
	}
	s := &Server{o: o, hosts: map[string]*Host{}, repos: map[int]*repo{}, data: map[int]map[string]bool{},
		scans: map[string]*scanDef{}, results: map[string]*scanResult{}, files: map[string][]byte{}, next: 100}
	for i := range o.Hosts {
		h := o.Hosts[i]
		if a, err := netip.ParseAddr(h.IP); err == nil {
			h.IP = a.String()
			s.hosts[h.IP] = &h
		}
	}
	for _, r := range o.Repositories {
		rp := &repo{Named: r, format: "universal", ipRange: "10.0.0.0/8", group: "fullAccess", created: 1000 + int64(r.ID),
			lifetimes: map[string]string{"activeVulnsLifetime": "1", "passiveVulnsLifetime": "1",
				"complianceVulnsLifetime": "1", "mitigatedVulnsLifetime": "1"}}
		if f, ok := o.RepositoryFormats[r.ID]; ok {
			rp.format = f
		}
		if v, ok := o.RepositoryRanges[r.ID]; ok {
			rp.ipRange = v
		}
		if slices.Contains(o.HiddenRepositories, r.ID) {
			rp.group = ""
		}
		s.repos[r.ID] = rp
		s.data[r.ID] = map[string]bool{}
	}
	return s
}

// ActiveIPs is the licence count: unique addresses, across repositories,
// holding a plugin outside DiscoveryPlugins.
func (s *Server) ActiveIPs() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.activeLocked(nil)
}

func (s *Server) activeLocked(extra []string) int {
	seen := map[string]bool{}
	count := func(ip string) {
		if h := s.hosts[ip]; h != nil && h.Alive && licensed(h) {
			seen[ip] = true
		}
	}
	for _, ips := range s.data {
		for ip := range ips {
			count(ip)
		}
	}
	for _, ip := range extra {
		count(ip)
	}
	return len(seen)
}

func licensed(h *Host) bool {
	for _, v := range h.Vulns {
		if !DiscoveryPlugins[v.PluginID] {
			return true
		}
	}
	return false
}

// Handler serves the REST API under /rest.
func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rw := &statusWriter{ResponseWriter: w, status: 200}
		s.serve(rw, r)
		if s.Log != nil {
			s.Log(fmt.Sprintf("%s %s %d", r.Method, r.URL.Path, rw.status))
		}
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) { w.status = code; w.ResponseWriter.WriteHeader(code) }

// Messages of the HTTP 400 answers to API key problems. The API key
// authorization guide documents the status and the causes, not the texts.
const (
	msgInvalidKeys = "Invalid API keys: the access key and secret key are not recognized"
	msgPermission  = "The user associated with the API key has insufficient permissions for the request"
)

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	key := r.Header.Get("x-apikey")
	admin := s.o.AdminAccessKey != "" && key == fmt.Sprintf("accesskey=%s; secretkey=%s;", s.o.AdminAccessKey, s.o.AdminSecretKey)
	if !admin && key != fmt.Sprintf("accesskey=%s; secretkey=%s;", s.o.AccessKey, s.o.SecretKey) {
		writeError(w, 400, 74, msgInvalidKeys)
		return
	}
	if s.o.AdminAccessKey != "" && !admin && strings.HasPrefix(r.URL.Path, "/rest/repository") && r.Method != http.MethodGet {
		writeError(w, 400, 143, msgPermission)
		return
	}
	if admin && r.URL.Path == "/rest/analysis" {
		// Administrators do not have access to the data collected.
		writeError(w, 400, 143, msgPermission)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	p := strings.TrimPrefix(r.URL.Path, "/rest")
	seg := strings.Split(strings.Trim(p, "/"), "/")
	switch {
	case p == "/system" && r.Method == http.MethodGet:
		writeOK(w, map[string]any{"version": s.o.Version, "buildID": "mock"})
	case p == "/status" && r.Method == http.MethodGet:
		writeOK(w, map[string]any{"licenseStatus": s.o.LicenseStatus, "licensedIPs": strconv.Itoa(s.o.LicensedIPs),
			"activeIPs": strconv.Itoa(s.activeLocked(nil))})
	case p == "/v1/license" && r.Method == http.MethodGet && versionAtLeast(s.o.Version, 6, 9):
		writeOK(w, map[string]any{"status": s.o.LicenseStatus, "type": "SC", "blades": map[string]any{"sc": map[string]any{
			"enabled": true, "limit": strconv.Itoa(s.o.LicensedIPs), "used": s.activeLocked(nil), "status": s.o.LicenseStatus}}})
	case p == "/repository" && r.Method == http.MethodGet:
		list := make([]map[string]any, 0, len(s.repos))
		for _, rep := range s.repoList() {
			if admin || rep.group != "" {
				list = append(list, s.repoJSON(rep, admin))
			}
		}
		writeOK(w, list)
	case len(seg) == 2 && seg[0] == "repository" && r.Method == http.MethodGet:
		id, _ := strconv.Atoi(seg[1])
		rep, ok := s.repos[id]
		if !ok || (!admin && rep.group == "") {
			writeError(w, 403, 143, "Repository not found")
			return
		}
		writeOK(w, s.repoJSON(rep, admin))
	case p == "/repository" && r.Method == http.MethodPost:
		s.createRepository(w, r)
	case len(seg) == 2 && seg[0] == "repository" && r.Method == http.MethodDelete:
		id, _ := strconv.Atoi(seg[1])
		if _, ok := s.repos[id]; !ok {
			writeError(w, 403, 143, "Repository not found")
			return
		}
		delete(s.repos, id)
		delete(s.data, id)
		writeOK(w, "")
	case p == "/file/upload" && r.Method == http.MethodPost:
		s.upload(w, r)
	case p == "/scanResult/import" && r.Method == http.MethodPost:
		s.importFile(w, r)
	case len(seg) == 3 && seg[0] == "scanResult" && seg[2] == "import" && r.Method == http.MethodPost:
		s.reimport(w, seg[1])
	case p == "/policy" && r.Method == http.MethodGet:
		writeOK(w, map[string]any{"usable": s.namedList(s.o.Policies), "manageable": []any{}})
	case p == "/zone" && r.Method == http.MethodGet:
		writeOK(w, s.namedList(s.o.Zones))
	case p == "/scan" && r.Method == http.MethodGet:
		var list []map[string]any
		for _, d := range s.scans {
			list = append(list, map[string]any{"id": d.id, "name": d.name, "schedule": map[string]any{"type": d.schedule}})
		}
		writeOK(w, map[string]any{"usable": list, "manageable": []any{}})
	case p == "/scan" && r.Method == http.MethodPost:
		s.createScan(w, r)
	case len(seg) == 2 && seg[0] == "scan" && r.Method == http.MethodDelete:
		if _, ok := s.scans[seg[1]]; !ok {
			writeError(w, 403, 143, "Scan not found")
			return
		}
		delete(s.scans, seg[1])
		writeOK(w, "")
	case len(seg) == 3 && seg[0] == "scan" && seg[2] == "launch" && r.Method == http.MethodPost:
		s.launch(w, seg[1])
	case p == "/scanResult" && r.Method == http.MethodGet:
		var list []map[string]any
		for _, res := range s.results {
			list = append(list, map[string]any{"id": res.id, "name": res.name, "status": res.status,
				"importStatus": res.importStatus, "repository": map[string]any{"id": strconv.Itoa(res.repo)}})
		}
		writeOK(w, map[string]any{"usable": list, "manageable": []any{}})
	case len(seg) == 2 && seg[0] == "scanResult" && r.Method == http.MethodGet:
		s.readResult(w, seg[1])
	case len(seg) == 3 && seg[0] == "scanResult" && seg[2] == "stop" && r.Method == http.MethodPost:
		s.stop(w, seg[1])
	case p == "/analysis" && r.Method == http.MethodPost:
		s.analysis(w, r)
	case len(seg) == 2 && seg[0] == "plugin" && r.Method == http.MethodGet:
		writeOK(w, map[string]any{"id": seg[1], "name": "Plugin " + seg[1], "type": "active",
			"family": map[string]any{"id": "1", "name": "General"}})
	default:
		writeError(w, 404, 404, "Unknown resource")
	}
}

func (s *Server) repoList() []*repo {
	out := make([]*repo, 0, len(s.repos))
	for _, r := range s.repos {
		out = append(out, r)
	}
	slices.SortFunc(out, func(a, b *repo) int { return a.ID - b.ID })
	return out
}

// repoJSON is a repository as GET /repository documents it: ipRange and
// lifetimes inside typeFields, organizations for an administrator only.
func (s *Server) repoJSON(rp *repo, admin bool) map[string]any {
	tf := map[string]any{"ipRange": rp.ipRange}
	for k, v := range rp.lifetimes {
		tf[k] = v
	}
	if rp.trending != "" {
		tf["trendingDays"] = rp.trending
	}
	m := map[string]any{"id": strconv.Itoa(rp.ID), "uuid": fmt.Sprintf("00000000-0000-4000-8000-%012d", rp.ID),
		"name": rp.Name, "description": "", "type": "Local", "dataFormat": rp.format,
		"createdTime": strconv.FormatInt(rp.created, 10), "typeFields": tf}
	if admin {
		m["organizations"] = []map[string]string{{"id": "1", "name": "Org", "groupAssign": rp.group}}
	}
	return m
}

func (s *Server) createRepository(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	b, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if json.Unmarshal(b, &body) != nil {
		writeError(w, 400, 146, "Invalid repository")
		return
	}
	str := func(k string) string { v, _ := body[k].(string); return v }
	name, format := str("name"), str("dataFormat")
	if name == "" || str("type") != "Local" {
		writeError(w, 400, 146, "Invalid repository")
		return
	}
	if versionAtLeast(s.o.Version, 6, 8) && format != "mobile" && format != "universal" {
		writeError(w, 400, 146, "Beginning in 6.8.0 the only allowed dataFormat for a new Local repository is mobile or universal")
		return
	}
	for _, rep := range s.repos {
		if rep.Name == name {
			writeError(w, 400, 144, "Name already exists")
			return
		}
	}
	id, _ := strconv.Atoi(s.id())
	rp := &repo{Named: Named{ID: id, Name: name}, format: format, ipRange: str("ipRange"), lifetimes: map[string]string{},
		trending: str("trendingDays"), created: int64(2000 + id)}
	for _, k := range []string{"activeVulnsLifetime", "passiveVulnsLifetime", "complianceVulnsLifetime", "mitigatedVulnsLifetime"} {
		v := str(k)
		if v == "" {
			v = map[string]string{"passiveVulnsLifetime": "7"}[k]
			if v == "" {
				v = "365"
			}
		}
		rp.lifetimes[k] = v
	}
	if orgs, ok := body["organizations"].([]any); ok {
		for _, o := range orgs {
			if m, ok := o.(map[string]any); ok && fmt.Sprint(m["id"]) == "1" {
				rp.group, _ = m["groupAssign"].(string)
			}
		}
	}
	s.repos[id] = rp
	s.data[id] = map[string]bool{}
	writeOK(w, map[string]any{"id": strconv.Itoa(id), "name": name})
}

func (s *Server) upload(w http.ResponseWriter, r *http.Request) {
	f, _, err := r.FormFile("Filedata")
	if err != nil {
		writeError(w, 400, 146, "No file uploaded")
		return
	}
	defer func() { _ = f.Close() }()
	b, _ := io.ReadAll(io.LimitReader(f, 8<<20))
	name := "f" + s.id()
	s.files[name] = b
	writeOK(w, map[string]any{"filename": name, "originalFilename": "upload"})
}

// nessusFile is the part of a Nessus v2 file the mock reads.
type nessusFile struct {
	Prefs []struct {
		Name  string `xml:"name"`
		Value string `xml:"value"`
	} `xml:"Policy>Preferences>ServerPreferences>preference"`
	Report struct {
		Name  string     `xml:"name,attr"`
		Hosts []struct{} `xml:"ReportHost"`
	} `xml:"Report"`
}

// importFile imports an uploaded file. A file with no ReportHost removes
// the data of every address in its TARGET preference from the repository
// at once, unless it is an agent repository (Tenable knowledge base).
func (s *Server) importFile(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Filename   string `json:"filename"`
		Repository struct {
			ID string `json:"id"`
		} `json:"repository"`
	}
	b, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if json.Unmarshal(b, &body) != nil {
		writeError(w, 400, 146, "Invalid import")
		return
	}
	content, ok := s.files[body.Filename]
	id, _ := strconv.Atoi(body.Repository.ID)
	rp, rok := s.repos[id]
	if !ok || !rok {
		writeError(w, 403, 143, "File or repository not found")
		return
	}
	var nf nessusFile
	if xml.Unmarshal(content, &nf) != nil {
		writeError(w, 400, 146, "Invalid scan result file")
		return
	}
	res := &scanResult{id: s.id(), name: nf.Report.Name, repo: id, status: "Completed", importStatus: "Finished"}
	s.results[res.id] = res
	if len(nf.Report.Hosts) > 0 || strings.EqualFold(rp.format, "agent") {
		writeOK(w, "")
		return
	}
	for _, pr := range nf.Prefs {
		if pr.Name != "TARGET" {
			continue
		}
		for _, ip := range s.expandAll(pr.Value) {
			delete(s.data[id], ip)
		}
	}
	writeOK(w, "")
}

// expandAll is every address with data or a host in an ipList (addresses
// and CIDR ranges), known host or not.
func (s *Server) expandAll(ipList string) []string {
	var out []string
	for _, t := range strings.Split(ipList, ",") {
		t = strings.TrimSpace(t)
		if pfx, err := netip.ParsePrefix(t); err == nil {
			for _, ips := range s.data {
				for ip := range ips {
					if a, _ := netip.ParseAddr(ip); pfx.Contains(a) {
						out = append(out, ip)
					}
				}
			}
		} else if a, err := netip.ParseAddr(t); err == nil {
			out = append(out, a.String())
		}
	}
	return out
}

// reimport imports a result again: a Blocked one is imported once its
// repository has room (next read), into a deleted repository it errors.
func (s *Server) reimport(w http.ResponseWriter, id string) {
	res, ok := s.results[id]
	if !ok {
		writeError(w, 403, 143, "Scan Result not found")
		return
	}
	if _, ok := s.repos[res.repo]; !ok {
		res.importStatus = "Error"
	} else if res.status == "Completed" || res.status == "Partial" {
		res.importStatus = "Importing"
	}
	writeOK(w, "")
}

// inRange reports whether every address of ipList is inside ipRange.
func inRange(ipRange string, addrs []string) bool {
	var pfx []netip.Prefix
	for _, part := range strings.Split(ipRange, ",") {
		if p, err := netip.ParsePrefix(strings.TrimSpace(part)); err == nil {
			pfx = append(pfx, p)
		} else if a, err := netip.ParseAddr(strings.TrimSpace(part)); err == nil {
			pfx = append(pfx, netip.PrefixFrom(a, a.BitLen()))
		}
	}
	for _, ip := range addrs {
		a, err := netip.ParseAddr(ip)
		if err != nil || !slices.ContainsFunc(pfx, func(p netip.Prefix) bool { return p.Contains(a) }) {
			return false
		}
	}
	return true
}

func versionAtLeast(v string, major, minor int) bool {
	parts := strings.SplitN(v, ".", 3)
	if len(parts) < 2 {
		return false
	}
	ma, _ := strconv.Atoi(parts[0])
	mi, _ := strconv.Atoi(parts[1])
	return ma > major || (ma == major && mi >= minor)
}

func (s *Server) namedList(in []Named) []map[string]any {
	out := make([]map[string]any, 0, len(in))
	for _, n := range in {
		out = append(out, map[string]any{"id": strconv.Itoa(n.ID), "name": n.Name})
	}
	return out
}

func (s *Server) id() string {
	s.next++
	return strconv.Itoa(s.next)
}

func (s *Server) createScan(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name       string `json:"name"`
		Type       string `json:"type"`
		IPList     string `json:"ipList"`
		Repository struct {
			ID string `json:"id"`
		} `json:"repository"`
		Policy struct {
			ID string `json:"id"`
		} `json:"policy"`
		MaxScanTime string `json:"maxScanTime"`
		Schedule    struct {
			Type string `json:"type"`
		} `json:"schedule"`
	}
	b, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if json.Unmarshal(b, &body) != nil || body.Name == "" || body.Type != "policy" {
		writeError(w, 400, 146, "Invalid scan definition")
		return
	}
	repo, _ := strconv.Atoi(body.Repository.ID)
	rp, ok := s.repos[repo]
	if !ok || rp.group == "" {
		writeError(w, 403, 143, "Repository not found")
		return
	}
	var addrs []string
	for _, t := range strings.Split(body.IPList, ",") {
		t = strings.TrimSpace(t)
		if p, err := netip.ParsePrefix(t); err == nil {
			addrs = append(addrs, p.Masked().Addr().String())
		} else if _, err := netip.ParseAddr(t); err == nil {
			addrs = append(addrs, t)
		}
	}
	if !inRange(rp.ipRange, addrs) {
		writeError(w, 403, 146, "One or more scan targets do not exist in the selected import repository.")
		return
	}
	pol, _ := strconv.Atoi(body.Policy.ID)
	if !slices.ContainsFunc(s.o.Policies, func(n Named) bool { return n.ID == pol }) {
		writeError(w, 403, 143, "Policy not found")
		return
	}
	d := &scanDef{id: s.id(), name: body.Name, ipList: body.IPList, repo: repo, maxScanTime: body.MaxScanTime,
		schedule: body.Schedule.Type}
	s.scans[d.id] = d
	writeOK(w, map[string]any{"id": d.id, "name": d.name})
}

func (s *Server) launch(w http.ResponseWriter, id string) {
	d, ok := s.scans[id]
	if !ok {
		writeError(w, 403, 143, "Scan not found")
		return
	}
	res := &scanResult{id: s.id(), name: d.name, repo: d.repo, targets: s.expand(d.ipList),
		status: "Queued", importStatus: "No Results"}
	s.results[res.id] = res
	writeOK(w, map[string]any{"scanID": d.id, "scanResult": map[string]any{"id": res.id, "name": res.name,
		"status": res.status, "repositoryID": strconv.Itoa(d.repo)}})
}

// expand turns an ipList into the known addresses it covers (addresses,
// CIDR ranges and DNS names of known hosts).
func (s *Server) expand(ipList string) []string {
	var out []string
	seen := map[string]bool{}
	add := func(ip string) {
		if !seen[ip] {
			seen[ip] = true
			out = append(out, ip)
		}
	}
	for _, t := range strings.Split(ipList, ",") {
		t = strings.TrimSpace(t)
		if pfx, err := netip.ParsePrefix(t); err == nil {
			for ip := range s.hosts {
				if a, _ := netip.ParseAddr(ip); pfx.Contains(a) {
					add(ip)
				}
			}
			continue
		}
		if a, err := netip.ParseAddr(t); err == nil {
			add(a.String())
			continue
		}
		for ip, h := range s.hosts {
			if strings.EqualFold(h.DNSName, t) {
				add(ip)
			}
		}
	}
	slices.Sort(out)
	return out
}

func (s *Server) readResult(w http.ResponseWriter, id string) {
	res, ok := s.results[id]
	if !ok {
		writeError(w, 403, 143, "Scan Result not found")
		return
	}
	s.advance(res)
	done := 0
	switch res.status {
	case "Completed", "Partial":
		done = len(res.targets)
	case "Running":
		done = len(res.targets) * res.reads / (s.o.RunningReads + 1)
	}
	writeOK(w, map[string]any{
		"id": res.id, "name": res.name, "status": res.status, "importStatus": res.importStatus,
		"running":  strconv.FormatBool(res.status == "Running" || res.status == "Queued"),
		"totalIPs": strconv.Itoa(len(res.targets)), "completedIPs": strconv.Itoa(done),
		"totalChecks": strconv.Itoa(len(res.targets) * 1000), "completedChecks": strconv.Itoa(res.checks),
		"repository": map[string]any{"id": strconv.Itoa(res.repo)},
	})
}

// advance moves a result one state on per read: Queued → Running (×
// RunningReads) → Completed + Importing → Finished or Blocked.
func (s *Server) advance(res *scanResult) {
	switch res.status {
	case "Queued":
		res.status = "Running"
	case "Running":
		res.reads++
		res.checks = len(res.targets) * 1000 * res.reads / (s.o.RunningReads + 1)
		if res.reads >= s.o.RunningReads {
			res.status, res.importStatus = "Completed", "Importing"
			res.checks = len(res.targets) * 1000
			res.scanned = s.alive(res.targets)
			if s.o.PartialScans || s.o.MaxTimeReached {
				res.status = "Partial"
				res.scanned = s.alive(res.targets[:len(res.targets)/2])
			}
			if s.o.MaxTimeReached {
				// Tenable.sc creates a rollover scan for the rest.
				d := &scanDef{id: s.id(), name: res.name + " (rollover)", repo: res.repo, schedule: "rollover"}
				s.scans[d.id] = d
			}
		}
	case "Completed", "Partial":
		if res.importStatus == "Importing" {
			s.importResult(res)
		}
	}
}

func (s *Server) alive(ips []string) []string {
	var out []string
	for _, ip := range ips {
		if h := s.hosts[ip]; h != nil && h.Alive {
			out = append(out, ip)
		}
	}
	return out
}

// importResult imports a result's hosts into its repository unless that
// would exceed the licence (Blocked, nothing imported).
func (s *Server) importResult(res *scanResult) {
	if len(res.scanned) == 0 {
		res.importStatus = "No Results"
		return
	}
	if s.activeLocked(res.scanned) > s.o.LicensedIPs {
		res.importStatus = "Blocked"
		return
	}
	if _, ok := s.repos[res.repo]; !ok {
		res.importStatus = "Error"
		return
	}
	for _, ip := range res.scanned {
		s.data[res.repo][ip] = true
	}
	res.importStatus = "Finished"
}

func (s *Server) stop(w http.ResponseWriter, id string) {
	res, ok := s.results[id]
	if !ok {
		writeError(w, 403, 143, "Scan Result not found")
		return
	}
	if res.status == "Running" || res.status == "Queued" {
		// What was scanned so far is kept: the first half of the targets.
		res.scanned = s.alive(res.targets[:len(res.targets)/2])
		res.status, res.importStatus = "Partial", "Importing"
	}
	writeOK(w, "")
}

type analysisBody struct {
	Type       string `json:"type"`
	DataSource string `json:"sourceType"`
	ScanID     string `json:"scanID"`
	Query      struct {
		Tool        string `json:"tool"`
		StartOffset int    `json:"startOffset"`
		EndOffset   int    `json:"endOffset"`
		Filters     []struct {
			FilterName string          `json:"filterName"`
			Value      json.RawMessage `json:"value"`
		} `json:"filters"`
	} `json:"query"`
}

func (s *Server) analysis(w http.ResponseWriter, r *http.Request) {
	var q analysisBody
	b, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if json.Unmarshal(b, &q) != nil || q.Type != "vuln" {
		writeError(w, 400, 146, "Invalid analysis query")
		return
	}
	var ips []string
	repoOf := map[string]int{}
	switch q.DataSource {
	case "individual":
		res, ok := s.results[q.ScanID]
		if !ok {
			writeError(w, 403, 143, "Scan Result not found")
			return
		}
		if res.importStatus == "Finished" {
			ips = res.scanned
			for _, ip := range ips {
				repoOf[ip] = res.repo
			}
		}
	case "cumulative":
		allowed := s.repoFilter(q)
		for _, rep := range s.repoList() {
			if allowed != nil && !allowed[rep.ID] {
				continue
			}
			for ip := range s.data[rep.ID] {
				if _, dup := repoOf[ip]; !dup {
					ips = append(ips, ip)
					repoOf[ip] = rep.ID
				}
			}
		}
		slices.Sort(ips)
	case "patched":
	default:
		writeError(w, 400, 146, "Invalid sourceType")
		return
	}
	sev := s.severityFilter(q)
	ipf := s.ipFilter(q)
	var rows []map[string]any
	for _, ip := range ips {
		if ipf != nil && !ipf[ip] {
			continue
		}
		h := s.hosts[ip]
		switch q.Query.Tool {
		case "sumip":
			rows = append(rows, s.hostRow(h, repoOf[ip]))
		case "vulndetails":
			for _, v := range append([]Vuln{{PluginID: "19506", Name: "Nessus Scan Information", Family: "Settings"}}, h.Vulns...) {
				if sev != nil && !sev[v.Severity] {
					continue
				}
				row := s.hostRow(h, repoOf[ip])
				row["pluginID"], row["pluginName"] = v.PluginID, v.Name
				row["severity"] = map[string]any{"id": strconv.Itoa(v.Severity)}
				row["port"], row["protocol"] = strconv.Itoa(v.Port), v.Protocol
				row["cve"], row["synopsis"], row["solution"] = v.CVE, v.Synopsis, v.Solution
				row["family"] = map[string]any{"id": "1", "name": v.Family}
				if v.CVSSV3 > 0 {
					row["cvssV3BaseScore"] = strconv.FormatFloat(v.CVSSV3, 'f', 1, 64)
				}
				now := strconv.FormatInt(time.Now().Unix(), 10)
				row["firstSeen"], row["lastSeen"] = now, now
				rows = append(rows, row)
			}
		default:
			writeError(w, 400, 146, "Unsupported tool")
			return
		}
	}
	start, end := max(q.Query.StartOffset, 0), q.Query.EndOffset
	if end <= 0 || end > len(rows) {
		end = len(rows)
	}
	if start > end {
		start = end
	}
	page := rows[start:end]
	if page == nil {
		page = []map[string]any{}
	}
	writeOK(w, map[string]any{"totalRecords": strconv.Itoa(len(rows)), "returnedRecords": strconv.Itoa(len(page)),
		"startOffset": strconv.Itoa(start), "endOffset": strconv.Itoa(end), "results": page})
}

func (s *Server) hostRow(h *Host, repo int) map[string]any {
	return map[string]any{"ip": h.IP, "dnsName": h.DNSName, "netbiosName": h.NetBIOS, "macAddress": h.MAC,
		"operatingSystem": h.OS, "repository": map[string]any{"id": strconv.Itoa(repo), "name": s.repoName(repo)}}
}

// repoFilter reads the documented repository filter, value {"id": N} (one
// object). Any other shape is ignored, as an unvalidated filter may be.
func (s *Server) repoName(id int) string {
	if r, ok := s.repos[id]; ok {
		return r.Name
	}
	return ""
}

func (s *Server) repoFilter(q analysisBody) map[int]bool {
	for _, f := range q.Query.Filters {
		if f.FilterName != "repository" {
			continue
		}
		var one struct {
			ID json.Number `json:"id"`
		}
		if json.Unmarshal(f.Value, &one) != nil || one.ID == "" {
			return nil
		}
		id, _ := strconv.Atoi(one.ID.String())
		return map[int]bool{id: true}
	}
	return nil
}

// ipFilter reads the ip filter: a comma-separated list of addresses.
func (s *Server) ipFilter(q analysisBody) map[string]bool {
	for _, f := range q.Query.Filters {
		if f.FilterName != "ip" {
			continue
		}
		var v string
		if json.Unmarshal(f.Value, &v) != nil {
			return nil
		}
		out := map[string]bool{}
		for _, p := range strings.Split(v, ",") {
			out[strings.TrimSpace(p)] = true
		}
		return out
	}
	return nil
}

// ScanDefinitions are the names of the scan definitions that exist.
func (s *Server) ScanDefinitions() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for _, d := range s.scans {
		out = append(out, d.name)
	}
	slices.Sort(out)
	return out
}

// MaxScanTimes are the maxScanTime values scans were created with, by name.
func (s *Server) MaxScanTimes() map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]string{}
	for _, d := range s.scans {
		out[d.name] = d.maxScanTime
	}
	return out
}

// RepositoryNames are the repositories that exist, by id.
func (s *Server) RepositoryNames() map[int]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[int]string{}
	for id, r := range s.repos {
		out[id] = r.Name
	}
	return out
}

// RepositoryHolds reports whether repository id holds data for ip.
func (s *Server) RepositoryHolds(id int, ip string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.data[id][ip]
}

// SetRepositoryGroup sets organization 1's groupAssign on repository id
// (for tests of a repository the user cannot see).
func (s *Server) SetRepositoryGroup(id int, group string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r, ok := s.repos[id]; ok {
		r.group = group
	}
}

func (s *Server) severityFilter(q analysisBody) map[int]bool {
	for _, f := range q.Query.Filters {
		if f.FilterName != "severity" {
			continue
		}
		var v string
		if json.Unmarshal(f.Value, &v) != nil {
			return map[int]bool{}
		}
		out := map[int]bool{}
		for _, p := range strings.Split(v, ",") {
			n, err := strconv.Atoi(strings.TrimSpace(p))
			if err == nil {
				out[n] = true
			}
		}
		return out
	}
	return nil
}

func writeOK(w http.ResponseWriter, response any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"type": "regular", "response": response, "error_code": 0,
		"error_msg": "", "warnings": []any{}, "timestamp": time.Now().Unix()})
}

func writeError(w http.ResponseWriter, status, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"type": "regular", "response": "", "error_code": code,
		"error_msg": msg, "warnings": []any{}, "timestamp": time.Now().Unix()})
}

// SetLicensedIPs changes the IP licence (a new licence was uploaded).
func (s *Server) SetLicensedIPs(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.o.LicensedIPs = n
}

// RepoInfo is a repository definition as the mock holds it.
type RepoInfo struct {
	ID          int
	DataFormat  string
	IPRange     string
	Lifetimes   map[string]string
	GroupAssign string
}

// Repository returns the repository named name.
func (s *Server) Repository(name string) (RepoInfo, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.repos {
		if r.Name == name {
			lt := map[string]string{}
			for k, v := range r.lifetimes {
				lt[k] = v
			}
			return RepoInfo{ID: r.ID, DataFormat: r.format, IPRange: r.ipRange, Lifetimes: lt, GroupAssign: r.group}, true
		}
	}
	return RepoInfo{}, false
}
