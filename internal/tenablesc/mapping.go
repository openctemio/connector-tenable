package tenablesc

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/openctemio/sdk-go/pkg/ctis"
)

// Tool identity of every report the connector pushes. Commands name the
// same tool (payload "scanner"), so result binding accepts the reports.
const (
	ToolName   = "tenable_sc"
	toolVendor = "Tenable"
)

// Tenable states of a vulnerability row.
const (
	stateOpen      = "open"
	stateMitigated = "mitigated"
)

// Per-field caps (api RFC-040 §5.4, RFC-047 §8.4).
const (
	capTitle       = 512
	capLongText    = 16 << 10
	capEvidence    = 64 << 10
	capReference   = 2 << 10
	maxReferences  = 50
	maxCVEs        = 200
	capComment     = 1 << 10
	capShort       = 1 << 10
	capHostname    = 253
	capIdentifier  = 128
	capVersionText = 64
)

var (
	cveRE      = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)
	hostnameRE = regexp.MustCompile(`^[a-z0-9_]([a-z0-9_-]{0,62})(\.[a-z0-9_]([a-z0-9_-]{0,62}))*$`)
	// minTimestamp: anything before 1990 is not a real Tenable date (Tenable
	// uses -1 and 0 for "unknown").
	minTimestamp = time.Date(1990, 1, 1, 0, 0, 0, 0, time.UTC)
)

// mapper turns rows into CTIS assets and findings.
type mapper struct {
	now     time.Time
	plugins map[string]*plugin // enrichment, may miss ids
}

// Tenable system name of every source_refs entry the connector writes. The
// ids carry their kind as a prefix: plugin:<id>, vuln:<uuid>, host:<uuid>,
// instance:<name>, scan_result:<id>.
const sourceSystem = "tenable_sc"

// hostKey identifies the assets a row belongs to. asset is the machine
// (a host named by its DNS name, or an ip_address); ipAsset is the machine's
// address as an asset of its own when the host is named by a DNS name.
type hostKey struct {
	assetID string
	asset   ctis.Asset
	ipAsset *ctis.Asset
	ip      string
	repo    string
	hostID  string
}

// assets returns every asset the machine contributes to a document.
func (h hostKey) assets() []ctis.Asset {
	out := []ctis.Asset{h.asset}
	if h.ipAsset != nil {
		out = append(out, *h.ipAsset)
	}
	return out
}

// relationships links the machine's name to its address.
func (h hostKey) relationships() []ctis.Relationship {
	if h.ipAsset == nil {
		return nil
	}
	return []ctis.Relationship{{Type: ctis.RelResolvesTo, FromRef: h.asset.ID, ToRef: h.ipAsset.ID}}
}

// docRef builds a document-local reference: it follows
// ctis.DocumentRefPattern, is never UUID-shaped, and is at most 255
// characters (a longer value is replaced by its digest).
func docRef(kind, value string) string {
	ref := kind + ":" + value
	if len(ref) <= 255 && refSafe(ref) {
		return ref
	}
	sum := sha256.Sum256([]byte(value))
	return kind + ":sha256-" + hex.EncodeToString(sum[:16])
}

func refSafe(s string) bool {
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case strings.ContainsRune("._:/@+=~%-", r):
		default:
			return false
		}
	}
	return s != ""
}

// host maps a row's host part. ok is false when the row names no usable
// host (no valid IP and no valid DNS name). Every value is the canonical
// form of its asset type.
func (m *mapper) host(r *vulnRow) (hostKey, bool) {
	ip := canonical(ctis.AssetTypeIPAddress, normalizeIP(r.IP))
	fqdn := canonical(ctis.AssetTypeHost, normalizeHostname(r.DNSName))
	if fqdn == "" && ip == "" {
		return hostKey{}, false
	}
	netbios := sanitizeText(r.NetBIOSName, capIdentifier)
	hostUUID := firstNonEmpty(sanitizeIdentifier(r.HostUUID), sanitizeIdentifier(r.UUID))
	repoID := sanitizeIdentifier(string(r.Repository.ID))

	asset := ctis.Asset{Properties: ctis.Properties{}}
	var ipAsset *ctis.Asset
	if fqdn != "" {
		asset.Type, asset.Value, asset.Name = ctis.AssetTypeHost, fqdn, fqdn
		asset.ID = docRef("host", fqdn)
		if ip != "" {
			ia := ctis.Asset{ID: docRef("ip", ip), Type: ctis.AssetTypeIPAddress, Value: ip, Name: ip}
			ipAsset = &ia
		}
	} else {
		asset.Type, asset.Value, asset.Name = ctis.AssetTypeIPAddress, ip, ip
		asset.ID = docRef("ip", ip)
		if netbios != "" {
			asset.Name = netbios
		}
	}
	if netbios != "" || fqdn != "" {
		asset.IdentityHints = &ctis.IdentityHints{FQDN: fqdn, NetBIOSName: netbios}
	}
	if os := sanitizeText(r.OperatingSystem, capShort); os != "" {
		asset.Technologies = []ctis.Technology{{Name: os, Categories: []string{"operating_system"}}}
	}
	if hostUUID != "" {
		asset.SourceRefs = []ctis.SourceRef{{System: sourceSystem, ID: "host:" + hostUUID}}
	}
	setStr(asset.Properties, "tenable_repository_id", repoID)
	setStr(asset.Properties, "tenable_repository", sanitizeText(r.Repository.Name, capIdentifier))
	if v, ok := clampRange(r.ACRScore, 1, 10); ok {
		asset.Properties["tenable_acr"] = v
	}
	if v, ok := clampRange(r.AssetExposureScore, 0, 1000); ok {
		asset.Properties["tenable_aes"] = v
	}
	if len(asset.Properties) == 0 {
		asset.Properties = nil
	}
	if macs := splitMACs(r.MACAddress); len(macs) > 0 {
		asset.Identifiers = &ctis.AssetIdentifiers{MACAddresses: macs}
	}
	return hostKey{assetID: asset.ID, asset: asset, ipAsset: ipAsset, ip: ip, repo: repoID, hostID: hostUUID}, true
}

// canonical returns the canonical form of value for an asset type, or ""
// when it has none (the value is then not used as an asset).
func canonical(t ctis.AssetType, value string) string {
	if value == "" {
		return ""
	}
	c, err := ctis.CanonicalAssetValue(t, value)
	if err != nil {
		return ""
	}
	return c
}

// serviceOf names the service a finding's port belongs to. ok is false for a
// host-level finding (no port) or a protocol that is not tcp, udp or sctp
// (icmp findings belong to the host).
func serviceOf(h hostKey, port int, proto string) (a ctis.Asset, rel ctis.Relationship, ok bool) {
	if port < 1 || port > 65535 {
		return a, rel, false
	}
	hostValue := firstNonEmpty(h.asset.Value)
	value, err := ctis.CanonicalService(hostValue, port, proto)
	if err != nil {
		return a, rel, false
	}
	tr := ctis.Transport(strings.ToLower(proto))
	a = ctis.Asset{
		ID:    docRef("svc", strings.NewReplacer("[", "", "]", "").Replace(value)),
		Type:  ctis.AssetTypeService,
		Value: value,
		Name:  value,
		Technical: &ctis.AssetTechnical{Service: &ctis.ServiceTechnical{
			Port: port, Transport: tr, State: ctis.PortOpen,
		}},
	}
	rel = ctis.Relationship{Type: ctis.RelExposes, FromRef: h.asset.ID, ToRef: a.ID}
	return a, rel, true
}

// rowAssets are the assets and relationships one finding adds to a report
// besides its own finding: the machine, and the service a port names.
type rowAssets struct {
	assets []ctis.Asset
	rels   []ctis.Relationship
}

// finding maps a vulnerability row (state open or mitigated). The finding
// belongs to the service asset when the row names a tcp/udp/sctp port, and
// to the machine otherwise.
func (m *mapper) finding(r *vulnRow, h hostKey, state string) (ctis.Finding, rowAssets) {
	pluginID := sanitizeIdentifier(string(r.PluginID))
	p := m.plugins[pluginID]
	title := sanitizeText(r.PluginName, capTitle)
	if title == "" && p != nil {
		title = sanitizeText(p.Name, capTitle)
	}
	if title == "" {
		title = "Tenable plugin " + pluginID
	}
	family := sanitizeText(r.Family.Name, capIdentifier)
	if family == "" && p != nil {
		family = sanitizeText(p.Family.Name, capIdentifier)
	}
	proto := strings.ToLower(sanitizeIdentifier(r.Protocol))
	port := int(r.Port)
	if port < 0 || port > 65535 {
		port = 0
	}
	hostRef := firstNonEmpty(h.ip, h.asset.Value)

	ra := rowAssets{assets: h.assets(), rels: h.relationships()}
	assetRef := h.assetID
	if svc, rel, ok := serviceOf(h, port, proto); ok {
		ra.assets = append(ra.assets, svc)
		ra.rels = append(ra.rels, rel)
		assetRef = svc.ID
	}

	f := ctis.Finding{
		Type:     ctis.FindingTypeVulnerability,
		Title:    title,
		Severity: mapSeverity(int64(r.Severity.ID)),
		AssetRef: assetRef,
		RuleID:   pluginID,
		RuleName: title,
		Category: family,
		Fingerprint: fmt.Sprintf("%s:%s:%s:%s:%d/%s",
			ToolName, h.repo, hostRef, pluginID, port, proto),
		Native: &ctis.NativeIdentity{Scheme: ctis.NativeSchemeNessus, VulnID: pluginID, Family: family},
	}
	if pluginID != "" {
		f.SourceRefs = append(f.SourceRefs, ctis.SourceRef{System: sourceSystem, ID: "plugin:" + pluginID})
	}
	if vu := sanitizeIdentifier(r.VulnUUID); vu != "" {
		f.SourceRefs = append(f.SourceRefs, ctis.SourceRef{System: sourceSystem, ID: "vuln:" + vu})
	}
	f.Description = joinNonEmpty("\n\n",
		sanitizeText(r.Synopsis, capLongText), sanitizeText(r.Description, capLongText))
	if len(f.Description) > capLongText {
		f.Description = sanitizeText(f.Description, capLongText)
	}
	if ev := sanitizeText(r.PluginText, capEvidence); ev != "" {
		f.EvidenceItems = []ctis.EvidenceItem{{Kind: ctis.EvidenceKindRawText, Version: 1, Label: "plugin output", Text: ev}}
	}
	if port > 0 {
		n := &ctis.NetworkLocation{Host: h.asset.Value, Port: port}
		if tr := ctis.Transport(proto); tr == ctis.TransportTCP || tr == ctis.TransportUDP || tr == ctis.TransportSCTP {
			n.Transport = tr
		}
		f.Network = n
	}
	if t := m.timestamp(r.FirstSeen); t != nil {
		f.FirstSeenAt = t
	}
	if t := m.timestamp(r.LastSeen); t != nil {
		f.LastSeenAt = t
	}
	if state == stateMitigated {
		f.Status = ctis.FindingStatusResolved
	}
	if lm := m.timestamp(r.LastMitigated); lm != nil {
		f.SourceLifecycle = &ctis.SourceLifecycle{LastFixedAt: lm}
	}

	f.Vulnerability = m.vulnerability(r, p)
	f.Scores = m.scores(r, p)
	if sol := sanitizeText(r.Solution, capLongText); sol != "" && !strings.EqualFold(sol, "n/a") {
		rem := &ctis.Remediation{Recommendation: sol}
		if t := m.date(r.PatchPubDate, pluginInt(p, func(p *plugin) flexInt { return p.PatchPubDate })); t != nil {
			rem.PatchPublishedAt = t
			rem.IsFixAvailable = ctis.Bool(true)
			rem.SolutionType = ctis.SolutionTypeVendorFix
		}
		f.Remediation = rem
	}
	if f.Remediation == nil {
		if t := m.date(r.PatchPubDate, pluginInt(p, func(p *plugin) flexInt { return p.PatchPubDate })); t != nil {
			f.Remediation = &ctis.Remediation{PatchPublishedAt: t, IsFixAvailable: ctis.Bool(true), SolutionType: ctis.SolutionTypeVendorFix}
		}
	}
	seeAlso := r.SeeAlso
	if seeAlso == "" && p != nil {
		seeAlso = p.SeeAlso
	}
	f.References = references(seeAlso)
	if bool(r.AcceptRisk) {
		f.Suppression = &ctis.Suppression{
			Kind: "risk_accepted", Status: "accepted",
			Reason: sanitizeText(r.AcceptRiskRuleComment, capComment),
		}
	}

	props := ctis.Properties{}
	setStr(props, "tenable_check_type", sanitizeText(r.CheckType, capIdentifier))
	if p != nil {
		setStr(props, "tenable_plugin_type", sanitizeText(p.Type, capIdentifier))
	}
	m.setDate(props, "tenable_plugin_pub_date", r.PluginPubDate, pluginInt(p, func(p *plugin) flexInt { return p.PluginPubDate }))
	m.setDate(props, "tenable_plugin_mod_date", r.PluginModDate, pluginInt(p, func(p *plugin) flexInt {
		if p.PluginModDate != 0 {
			return p.PluginModDate
		}
		return p.ModifiedTime
	}))
	ease := r.ExploitEase
	if p != nil {
		ease = firstNonEmpty(ease, p.ExploitEase)
	}
	setStr(props, "tenable_exploit_ease", sanitizeText(ease, capShort))
	frameworks := r.ExploitFrameworks
	if p != nil {
		frameworks = firstNonEmpty(frameworks, p.ExploitFrameworks)
	}
	setStr(props, "tenable_exploit_frameworks", sanitizeText(frameworks, capShort))
	if bool(r.RecastRisk) {
		props["tenable_recast_risk"] = true
	}
	setStr(props, "tenable_recast_risk_comment", sanitizeText(r.RecastRiskRuleComment, capComment))
	if bool(r.HasBeenMitigated) {
		props["tenable_previously_mitigated"] = true
	}
	setStr(props, "tenable_risk_factor", sanitizeText(r.RiskFactor, capIdentifier))
	xrefs := r.XRefs
	if xrefs == "" && p != nil {
		xrefs = p.XRefs
	}
	setStr(props, "tenable_xrefs", sanitizeText(xrefs, capShort))
	setStr(props, "tenable_bid", sanitizeText(r.BID, capShort))
	if len(props) > 0 {
		f.Properties = props
	}
	return f, ra
}

// scores maps Tenable's numeric ratings to scores[]: CVSS v3 (or v2 when
// there is no v3) and v4, Tenable's VPR as a vendor score, and EPSS.
func (m *mapper) scores(r *vulnRow, p *plugin) []ctis.Score {
	var out []ctis.Score
	f64 := func(v float64) *float64 { return &v }
	if s, ok := clampRange(r.CVSSV3BaseScore, 0, 10); ok {
		// The minor version comes from the vector; Tenable does not state it
		// otherwise.
		ver := "3.1"
		if ctis.CVSSVersionOfVector(sanitizeText(r.CVSSV3Vector, capIdentifier)) == "3.0" {
			ver = "3.0"
		}
		out = append(out, ctis.Score{System: ctis.ScoreSystemCVSS, Version: ver, Vector: cvssVector(r.CVSSV3Vector, ver), Value: f64(s), Source: "tenable"})
	} else if s, ok := clampRange(r.BaseScore, 0, 10); ok {
		out = append(out, ctis.Score{System: ctis.ScoreSystemCVSS, Version: "2.0", Vector: cvssVector(r.CVSSVector, "2.0"), Value: f64(s), Source: "tenable"})
	}
	if s, ok := clampRange(r.CVSSV4BaseScore, 0, 10); ok {
		out = append(out, ctis.Score{System: ctis.ScoreSystemCVSS, Version: "4.0", Vector: cvssVector(r.CVSSV4Vector, "4.0"), Value: f64(s), Source: "tenable"})
	}
	vpr := r.VPRScore
	if !vpr.Set && p != nil {
		vpr = p.VPRScore
	}
	if s, ok := clampRange(vpr, 0, 10); ok {
		out = append(out, ctis.Score{System: ctis.ScoreSystemVendor, Label: "vpr", Value: f64(s), Source: "tenable"})
	}
	if p != nil {
		if e, ok := epss(p.EPSSScore); ok {
			out = append(out, ctis.Score{System: ctis.ScoreSystemEPSS, Value: f64(e), Source: "tenable"})
		}
	}
	return out
}

// cvssVector keeps a vector only when it belongs to the stated CVSS
// version (the score would otherwise be rejected).
func cvssVector(vec, version string) string {
	vec = sanitizeText(vec, capIdentifier)
	if vec == "" {
		return ""
	}
	if got := ctis.CVSSVersionOfVector(vec); got != version && (got != "" || version != "2.0") {
		return ""
	}
	return vec
}

func (m *mapper) vulnerability(r *vulnRow, p *plugin) *ctis.VulnerabilityDetails {
	v := &ctis.VulnerabilityDetails{}
	for _, c := range splitCVEs(r.CVE) {
		v.AddID(c, "tenable")
	}
	cpe := r.CPE
	if cpe == "" && p != nil {
		cpe = p.CPE
	}
	v.CPE = sanitizeText(firstLine(cpe), capShort)
	var pub flexInt
	if r.VulnPubDate != 0 {
		pub = r.VulnPubDate
	} else if p != nil {
		pub = p.VulnPubDate
	}
	v.PublishedAt = m.timestamp(pub)
	if bool(r.ExploitAvailable) || (p != nil && bool(p.ExploitAvailable)) {
		v.ThreatSignals = append(v.ThreatSignals, ctis.ThreatSignal{
			Type: ctis.ThreatSignalPublicExploit, Source: "tenable", AsOf: ptr(m.now),
		})
	}
	if len(v.IDs) == 0 && v.CPE == "" && len(v.ThreatSignals) == 0 && v.PublishedAt == nil {
		return nil
	}
	return v
}

func ptr[T any](v T) *T { return &v }

// date reads a Tenable epoch date, falling back to the plugin's.
func (m *mapper) date(v, fallback flexInt) *time.Time {
	if t := m.timestamp(v); t != nil {
		return t
	}
	return m.timestamp(fallback)
}

func pluginInt(p *plugin, get func(*plugin) flexInt) flexInt {
	if p == nil {
		return 0
	}
	return get(p)
}

func (m *mapper) setDate(props ctis.Properties, key string, v, fallback flexInt) {
	t := m.timestamp(v)
	if t == nil {
		t = m.timestamp(fallback)
	}
	if t != nil {
		props[key] = t.Format(time.RFC3339)
	}
}

// timestamp reads epoch seconds; implausible values are dropped.
func (m *mapper) timestamp(v flexInt) *time.Time {
	if v <= 0 {
		return nil
	}
	t := time.Unix(int64(v), 0).UTC()
	if t.Before(minTimestamp) || t.After(m.now.Add(24*time.Hour)) {
		return nil
	}
	return &t
}

func mapSeverity(n int64) ctis.Severity {
	switch n {
	case 4:
		return ctis.SeverityCritical
	case 3:
		return ctis.SeverityHigh
	case 2:
		return ctis.SeverityMedium
	case 1:
		return ctis.SeverityLow
	default:
		return ctis.SeverityInfo
	}
}

func clampRange(f flexFloat, lo, hi float64) (float64, bool) {
	if !f.Set || f.V != f.V || f.V < lo || f.V > hi { // NaN check: f.V != f.V
		return 0, false
	}
	return f.V, true
}

// epss accepts a probability (0..1) or a percentage (Tenable shows both).
func epss(f flexFloat) (float64, bool) {
	if !f.Set || f.V != f.V || f.V < 0 {
		return 0, false
	}
	switch {
	case f.V <= 1:
		return f.V, true
	case f.V <= 100:
		return f.V / 100, true
	}
	return 0, false
}

func splitCVEs(s string) []string {
	var out []string
	seen := map[string]bool{}
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || unicode.IsSpace(r) }) {
		c := strings.ToUpper(strings.TrimSpace(f))
		if !cveRE.MatchString(c) || seen[c] {
			continue
		}
		seen[c] = true
		out = append(out, c)
		if len(out) == maxCVEs {
			break
		}
	}
	return out
}

func references(s string) []string {
	var out []string
	seen := map[string]bool{}
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == '\n' || r == '\r' || r == ' ' || r == '\t' }) {
		f = strings.TrimSpace(f)
		if f == "" || len(f) > capReference || seen[f] {
			continue
		}
		u, err := url.Parse(f)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			continue
		}
		clean := sanitizeText(f, capReference)
		if clean != f {
			continue
		}
		seen[f] = true
		out = append(out, f)
		if len(out) == maxReferences {
			break
		}
	}
	return out
}

func normalizeIP(s string) string {
	ip := net.ParseIP(strings.TrimSpace(s))
	if ip == nil {
		return ""
	}
	return ip.String()
}

func normalizeHostname(s string) string {
	h := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), "."))
	if h == "" || len(h) > capHostname || net.ParseIP(h) != nil || !hostnameRE.MatchString(h) {
		return ""
	}
	return h
}

// splitMACs splits a MAC list (newline, space or comma separated), lower
// case, de-duplicated.
func splitMACs(raw string) []string {
	var out []string
	seen := map[string]bool{}
	for _, f := range strings.FieldsFunc(raw, func(r rune) bool {
		return r == '\n' || r == '\r' || r == ' ' || r == '\t' || r == ','
	}) {
		mac := strings.ToLower(f)
		if _, err := net.ParseMAC(mac); err != nil || seen[mac] {
			continue
		}
		seen[mac] = true
		out = append(out, mac)
		if len(out) == 32 {
			break
		}
	}
	return out
}

// sanitizeText makes a Tenable string safe to carry: valid UTF-8, no NUL,
// no C0/C1 controls except tab and newline, no bidi overrides, at most max
// bytes (cut at a rune boundary), trimmed.
func sanitizeText(s string, max int) string {
	if s == "" {
		return ""
	}
	s = strings.ToValidUTF8(s, "�")
	var b strings.Builder
	b.Grow(min(len(s), max))
	for _, r := range s {
		switch {
		case r == '\t' || r == '\n':
		case r == '\r':
			continue
		case r < 0x20 || (r >= 0x7f && r <= 0x9f):
			continue
		case (r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069) || r == 0x200e || r == 0x200f:
			continue
		}
		if b.Len()+utf8.RuneLen(r) > max {
			break
		}
		b.WriteRune(r)
	}
	return strings.TrimSpace(b.String())
}

var identifierRE = regexp.MustCompile(`^[A-Za-z0-9._:\-]+$`)

// sanitizeIdentifier keeps a short id-like value (plugin id, uuid,
// repository id, protocol), or "".
func sanitizeIdentifier(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > capIdentifier || !identifierRE.MatchString(s) {
		return ""
	}
	return s
}

func setStr(p ctis.Properties, k, v string) {
	if v != "" {
		p[k] = v
	}
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func joinNonEmpty(sep string, vals ...string) string {
	out := make([]string, 0, len(vals))
	for _, v := range vals {
		if v != "" {
			out = append(out, v)
		}
	}
	return strings.Join(out, sep)
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		return s[:i]
	}
	return s
}
