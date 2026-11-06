package tenablesc

import (
	"context"
	"encoding/xml"
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/openctemio/connector-tenable/internal/tenablesc/scmock"
)

// Licence rotation against the documented Tenable.sc shapes (research 450):
// recycle never deletes before a verified replacement exists, purge
// removes only the previous batch's addresses and proves it, a Blocked
// import is imported again, and the guard refuses a licence that is not
// Valid.

func recycleEstateWith(t *testing.T, licensed int, opts func(*scmock.Options)) (*scmock.Server, *ScanExecutor) {
	t.Helper()
	mock, e, _ := newMockEstateWith(t, licensed, func(o *scmock.Options) {
		o.AdminAccessKey, o.AdminSecretKey = testAdminAccess, testAdminSecret
		o.Repositories = []scmock.Named{{ID: 5, Name: "openctem-rot-a"}, {ID: 7, Name: "Other team"}}
		if opts != nil {
			opts(o)
		}
	}, func(in *Instance) {
		in.Allow.Operations[OperationRecycle] = true
		in.Allow.ScanRepositories = []int{5, 7}
		in.Recycle = &Recycle{RepositoryNames: [2]string{"openctem-rot-a", "openctem-rot-b"},
			AdminAccessKey: Secret{testAdminAccess}, AdminSecretKey: Secret{testAdminSecret}}
	})
	return mock, e
}

func TestRecycle_68CreatesAUniversalReplacementBeforeDeleting(t *testing.T) {
	mock, e := recycleEstateWith(t, 5, func(o *scmock.Options) {
		o.Version = "6.8.1"
		o.RepositoryFormats = map[int]string{5: "IPv4"}
		o.RepositoryRanges = map[int]string{5: "10.30.0.0/16"}
	})
	if _, err := run(t, e, "cmd-b1", rotationPayload("1", false, "10.30.0.0/30")); err != nil {
		t.Fatal(err)
	}
	md, err := run(t, e, "cmd-b2", rotationPayload("2", true, "10.30.1.0/30"))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := mock.Repository("openctem-rot-a"); ok {
		t.Fatal("the old rotation repository was not deleted")
	}
	b, ok := mock.Repository("openctem-rot-b")
	if !ok {
		t.Fatal("no replacement")
	}
	// The definition came from typeFields and organizations.groupAssign.
	if b.DataFormat != "universal" || b.IPRange != "10.30.0.0/16" || b.Lifetimes["activeVulnsLifetime"] != "1" ||
		b.Lifetimes["mitigatedVulnsLifetime"] != "1" || b.GroupAssign != "fullAccess" {
		t.Fatalf("replacement %+v", b)
	}
	if md["recycled_repository_id"] != "5" || md["repository_id"] != b.ID || mock.ActiveIPs() != 2 {
		t.Fatalf("metadata %v active %d", md, mock.ActiveIPs())
	}
	// The next recycle goes back to the first name.
	if _, err := run(t, e, "cmd-b3", rotationPayload("3", true, "10.30.0.0/30")); err != nil {
		t.Fatal(err)
	}
	if _, ok := mock.Repository("openctem-rot-a"); !ok {
		t.Fatal("the names do not alternate")
	}
	if _, ok := mock.Repository("openctem-rot-b"); ok {
		t.Fatal("the second repository was not deleted")
	}
}

func TestRecycle_FailedCheckDeletesNothingAndIsFinishedLater(t *testing.T) {
	mock, e := recycleEstateWith(t, 10, func(o *scmock.Options) {
		o.RepositoryRanges = map[int]string{5: "10.30.0.0/24"}
	})
	if _, err := run(t, e, "cmd-b1", rotationPayload("1", false, "10.30.0.0/30")); err != nil {
		t.Fatal(err)
	}
	// The batch's targets are outside the range: the replacement fails the
	// checks and the old repository keeps its data.
	_, err := run(t, e, "cmd-b2", rotationPayload("2", true, "10.30.1.0/30"))
	if !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "nothing was deleted") {
		t.Fatalf("err %v", err)
	}
	if !mock.RepositoryHolds(5, "10.30.0.1") {
		t.Fatal("data deleted although the replacement failed")
	}
	b, ok := mock.Repository("openctem-rot-b")
	if !ok {
		t.Fatal("no replacement was created")
	}
	// A recycle that fits the range finishes it: the newer one is checked
	// again, then the older one is deleted; nothing new is created.
	md, err := run(t, e, "cmd-b3", rotationPayload("3", true, "10.30.0.0/30"))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := mock.Repository("openctem-rot-a"); ok || md["repository_id"] != b.ID || md["recycled_repository_id"] != "5" {
		t.Fatalf("metadata %v", md)
	}
}

func TestRecycle_HiddenReplacementIsNeverUsed(t *testing.T) {
	// The source grants the organization no group access: its replacement
	// would be invisible to the scanning user, so nothing is deleted.
	mock, e := recycleEstateWith(t, 10, func(o *scmock.Options) { o.HiddenRepositories = []int{5} })
	_, err := run(t, e, "cmd-b1", rotationPayload("1", true, "10.30.0.1"))
	if !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "cannot see") {
		t.Fatalf("err %v", err)
	}
	if _, ok := mock.Repository("openctem-rot-a"); !ok {
		t.Fatal("deleted")
	}
}

func TestRecycleConfig_TwoNames(t *testing.T) {
	scanAllow := Allow{Operations: map[string]bool{OperationScan: true, OperationRecycle: true}}
	for name, fr := range map[string]*fileRecycle{
		"retired single name": {RepositoryName: "openctem-rotation", AdminAccessKeyFile: "a", AdminSecretKeyFile: "b"},
		"one name":            {RepositoryNames: []string{"openctem-rot-a"}, AdminAccessKeyFile: "a", AdminSecretKeyFile: "b"},
		"three names":         {RepositoryNames: []string{"openctem-a", "openctem-b", "openctem-c"}, AdminAccessKeyFile: "a", AdminSecretKeyFile: "b"},
		"same name twice":     {RepositoryNames: []string{"openctem-a", "openctem-a"}, AdminAccessKeyFile: "a", AdminSecretKeyFile: "b"},
	} {
		if _, err := buildRecycle(fr, scanAllow); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	purgeAllow := Allow{Operations: map[string]bool{OperationScan: true, OperationPurge: true}}
	if p, err := buildPurge(&filePurge{RepositoryName: "openctem-rotation"}, purgeAllow); err != nil || p.RepositoryName != "openctem-rotation" {
		t.Fatalf("purge %v %v", p, err)
	}
	for name, tc := range map[string]struct {
		fp *filePurge
		a  Allow
	}{
		"no prefix":     {&filePurge{RepositoryName: "Datacenter"}, purgeAllow},
		"op no block":   {nil, purgeAllow},
		"block no op":   {&filePurge{RepositoryName: "openctem-r"}, Allow{Operations: map[string]bool{OperationScan: true}}},
		"purge no scan": {&filePurge{RepositoryName: "openctem-r"}, Allow{Operations: map[string]bool{OperationPurge: true}}},
	} {
		if _, err := buildPurge(tc.fp, tc.a); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}

// Purge.

func purgeEstate(t *testing.T, licensed int, opts func(*scmock.Options)) (*scmock.Server, *ScanExecutor) {
	t.Helper()
	mock, e, _ := newMockEstateWith(t, licensed, func(o *scmock.Options) {
		o.Repositories = []scmock.Named{{ID: 5, Name: "openctem-rot-p"}, {ID: 7, Name: "Other team"}}
		if opts != nil {
			opts(o)
		}
	}, func(in *Instance) {
		in.Allow.Operations[OperationPurge] = true
		in.Allow.ScanRepositories = []int{5, 7}
		in.Purge = &Purge{RepositoryName: "openctem-rot-p"}
	})
	return mock, e
}

func purgePayload(id string, prev string, prevTargets []string, targets ...string) map[string]any {
	p := mockPayload(id, targets...)
	p["repository_id"] = 0
	p["rotation_repository"] = true
	p["rotation_mode"] = "purge"
	p["licence_guard"] = map[string]any{"new_addresses": 2, "headroom": 0}
	if prev != "" {
		p["purge"] = map[string]any{"previous_command_id": prev, "targets": prevTargets}
	}
	return p
}

func TestPurge_RemovesThePreviousBatchAndFreesTheLicence(t *testing.T) {
	mock, e := purgeEstate(t, 3, nil)
	if _, err := run(t, e, "cmd-p1", purgePayload("1", "", nil, "10.30.0.0/30")); err != nil {
		t.Fatal(err)
	}
	if mock.ActiveIPs() != 2 {
		t.Fatalf("active %d", mock.ActiveIPs())
	}
	// Without a purge the guard refuses: 1 free, 2 needed.
	if _, err := run(t, e, "cmd-p2a", purgePayload("2", "", nil, "10.30.1.0/30")); !errors.Is(err, ErrLicenceCapacity) {
		t.Fatalf("err %v", err)
	}
	md, err := run(t, e, "cmd-p2", purgePayload("2", "cmd-p1", []string{"10.30.0.0/30"}, "10.30.1.0/30"))
	if err != nil {
		t.Fatal(err)
	}
	if mock.RepositoryHolds(5, "10.30.0.1") || md["purged_addresses"] != 3 || md["rotation_mode"] != "purge" || mock.ActiveIPs() != 2 {
		t.Fatalf("metadata %v active %d", md, mock.ActiveIPs())
	}
	if !mock.RepositoryHolds(5, "10.30.1.1") {
		t.Fatal("the new batch is not in the rotation repository")
	}
}

func TestPurge_Refusals(t *testing.T) {
	t.Run("a host outside the previous batch", func(t *testing.T) {
		mock, e := purgeEstate(t, 10, nil)
		if _, err := run(t, e, "cmd-p1", purgePayload("1", "", nil, "10.30.0.0/30")); err != nil {
			t.Fatal(err)
		}
		_, err := run(t, e, "cmd-p2", purgePayload("2", "cmd-p1", []string{"10.30.0.1"}, "10.30.1.0/30"))
		if !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "outside the previous batch") || !mock.RepositoryHolds(5, "10.30.0.2") {
			t.Fatalf("err %v", err)
		}
	})
	t.Run("agent repository", func(t *testing.T) {
		_, e := purgeEstate(t, 10, func(o *scmock.Options) { o.RepositoryFormats = map[int]string{5: "agent"} })
		if _, err := run(t, e, "c", purgePayload("1", "", nil, "10.30.0.1")); !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "agent") {
			t.Fatalf("err %v", err)
		}
	})
	t.Run("no previous result in the rotation repository", func(t *testing.T) {
		_, e := purgeEstate(t, 10, nil)
		_, err := run(t, e, "c", purgePayload("1", "cmd-never", []string{"10.30.0.0/30"}, "10.30.1.0/30"))
		if !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "not in the rotation repository") {
			t.Fatalf("err %v", err)
		}
	})
	t.Run("hostile purge payloads", func(t *testing.T) {
		_, e := purgeEstate(t, 10, nil)
		for name, mod := range map[string]func(p map[string]any){
			"list":         func(p map[string]any) { p["purge"].(map[string]any)["targets"] = []string{"10.30.0.1,10.0.0.0/8"} },
			"host name":    func(p map[string]any) { p["purge"].(map[string]any)["targets"] = []string{"db01.corp.example"} },
			"loopback":     func(p map[string]any) { p["purge"].(map[string]any)["targets"] = []string{"127.0.0.1"} },
			"wide range":   func(p map[string]any) { p["purge"].(map[string]any)["targets"] = []string{"10.0.0.0/8"} },
			"xml":          func(p map[string]any) { p["purge"].(map[string]any)["targets"] = []string{"10.0.0.1</value>"} },
			"bad command":  func(p map[string]any) { p["purge"].(map[string]any)["previous_command_id"] = "../x" },
			"no targets":   func(p map[string]any) { p["purge"].(map[string]any)["targets"] = []string{} },
			"without mode": func(p map[string]any) { delete(p, "rotation_mode") },
		} {
			p := purgePayload("1", "cmd-p1", []string{"10.30.0.0/30"}, "10.30.1.1")
			mod(p)
			if _, err := run(t, e, "c-"+strings.ReplaceAll(name, " ", "-"), p); !errors.Is(err, ErrRefused) {
				t.Fatalf("%s: err %v", name, err)
			}
		}
	})
	t.Run("recycle mode without a recycle block", func(t *testing.T) {
		_, e := purgeEstate(t, 10, nil)
		p := purgePayload("1", "", nil, "10.30.0.1")
		p["rotation_mode"] = "recycle"
		if _, err := run(t, e, "c", p); !errors.Is(err, ErrRefused) {
			t.Fatalf("err %v", err)
		}
	})
}

func TestPurge_UnverifiedWhenTheLicenceDoesNotDrop(t *testing.T) {
	mock, e := purgeEstate(t, 10, nil)
	// Another team holds the same addresses: removing them from the
	// rotation repository frees no licence.
	other := mockPayload("0", "10.30.0.0/30")
	other["repository_id"] = 7
	if _, err := run(t, e, "cmd-other", other); err != nil {
		t.Fatal(err)
	}
	if _, err := run(t, e, "cmd-p1", purgePayload("1", "", nil, "10.30.0.0/30")); err != nil {
		t.Fatal(err)
	}
	_, err := run(t, e, "cmd-p2", purgePayload("2", "cmd-p1", []string{"10.30.0.0/30"}, "10.30.1.0/30"))
	if !errors.Is(err, ErrPurgeUnverified) || !strings.Contains(err.Error(), "purge_unverified") {
		t.Fatalf("err %v", err)
	}
	if mock.RepositoryHolds(5, "10.30.1.1") {
		t.Fatal("scanned after an unverified purge")
	}
}

func TestPurgeFile(t *testing.T) {
	b, err := purgeFile("openctem-purge-cmd-1", []string{"10.0.0.1", "10.0.0.0/24", "10.0.0.1", "2001:db8::1"})
	if err != nil {
		t.Fatal(err)
	}
	var nf struct {
		Prefs []struct {
			Name  string `xml:"name"`
			Value string `xml:"value"`
		} `xml:"Policy>Preferences>ServerPreferences>preference"`
		Report struct {
			Name  string     `xml:"name,attr"`
			Hosts []struct{} `xml:"ReportHost"`
		} `xml:"Report"`
	}
	if err := xml.Unmarshal(b, &nf); err != nil {
		t.Fatal(err)
	}
	if len(nf.Prefs) != 1 || nf.Prefs[0].Name != "TARGET" || nf.Prefs[0].Value != "10.0.0.1,10.0.0.0/24,2001:db8::1" ||
		len(nf.Report.Hosts) != 0 || nf.Report.Name != "openctem-purge-cmd-1" {
		t.Fatalf("file %s", b)
	}
	for name, ips := range map[string][]string{
		"empty":       {},
		"xml":         {"10.0.0.1</value><preference>"},
		"list":        {"10.0.0.1,10.0.0.2"},
		"spaces":      {" 10.0.0.1"},
		"host name":   {"db01.corp.example"},
		"url":         {"http://10.0.0.1/"},
		"range form":  {"10.0.0.1-10.0.0.9"},
		"wide":        {"10.0.0.0/8"},
		"loopback":    {"127.0.0.1"},
		"metadata":    {"169.254.169.254"},
		"unspecified": {"0.0.0.0"},
		"control":     {"10.0.0.1\n"},
	} {
		if _, err := purgeFile("openctem-purge-x", ips); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	if _, err := purgeFile(`x"><Report name="y`, []string{"10.0.0.1"}); err == nil {
		t.Fatal("hostile report name accepted")
	}
}

// Blocked imports.

var scanResultIDRE = regexp.MustCompile(`scan_result_id=(\d+)`)

func TestBlocked_IsImportedAgainOnceCapacityIsFree(t *testing.T) {
	mock, e, p := newMockEstate(t, 3)
	if _, err := run(t, e, "cmd-1", mockPayload("1", "10.30.0.0/30")); err != nil {
		t.Fatal(err)
	}
	_, err := run(t, e, "cmd-2", mockPayload("2", "10.30.1.0/30"))
	if !errors.Is(err, ErrImportBlocked) {
		t.Fatalf("err %v", err)
	}
	m := scanResultIDRE.FindStringSubmatch(err.Error())
	if m == nil {
		t.Fatalf("no scan result id in %v", err)
	}
	id, _ := strconv.Atoi(m[1])
	re := mockPayload("3", "10.30.1.0/30")
	re["reimport_scan_result_id"] = id
	re["licence_guard"] = map[string]any{"new_addresses": 2, "headroom": 0}
	// Still no capacity: the guard refuses before importing again.
	if _, err := run(t, e, "cmd-3a", re); !errors.Is(err, ErrLicenceCapacity) {
		t.Fatalf("err %v", err)
	}
	mock.SetLicensedIPs(10)
	pushed := len(p.reports)
	md, err := run(t, e, "cmd-3", re)
	if err != nil {
		t.Fatal(err)
	}
	if md["reimported"] != true || md["coverage"] != CoverageFull || md["scan_result_id"] != m[1] || mock.ActiveIPs() != 4 || len(p.reports) == pushed {
		t.Fatalf("metadata %v active %d", md, mock.ActiveIPs())
	}
	// Only an OpenCTEM result in an allowed repository is imported again.
	re["reimport_scan_result_id"] = 99999
	if _, err := run(t, e, "cmd-4", re); err == nil {
		t.Fatal("re-imported an unknown result")
	}
	re["reimport_scan_result_id"] = id
	re["recycle_repository"] = true
	if _, err := run(t, e, "cmd-5", re); !errors.Is(err, ErrRefused) {
		t.Fatalf("err %v", err)
	}
}

// Licence guard and source.

func TestLicence_GuardRefusesAnInvalidLicence(t *testing.T) {
	for _, status := range []string{"Exceeded", "Locked", "Expired"} {
		_, e, _ := newMockEstateWith(t, 100, func(o *scmock.Options) { o.LicenseStatus = status }, nil)
		p := mockPayload("1", "10.30.0.1")
		p["licence_guard"] = map[string]any{"new_addresses": 1, "headroom": 0}
		if _, err := run(t, e, "c", p); !errors.Is(err, ErrLicenceCapacity) || !strings.Contains(err.Error(), status) {
			t.Fatalf("%s: err %v", status, err)
		}
	}
}

func TestLicence_V1On69(t *testing.T) {
	_, e, _ := newMockEstateWith(t, 100, func(o *scmock.Options) { o.Version = "6.9.0" }, nil)
	p := mockPayload("1", "10.30.0.1")
	p["licence_guard"] = map[string]any{"new_addresses": 1, "headroom": 0}
	md, err := run(t, e, "c", p)
	if err != nil {
		t.Fatal(err)
	}
	if md["license_source"] != "v1/license" || md["license_status"] != "Valid" || md["licensed_ips"] != int64(100) {
		t.Fatalf("metadata %v", md)
	}
	_, e, _ = newMockEstate(t, 100)
	if md, err = run(t, e, "c", p); err != nil || md["license_source"] != "status" {
		t.Fatalf("before 6.9: %v %v", md, err)
	}
}

// Tenable.sc's own maximum duration.

func TestScan_RolloverScanIsDeleted(t *testing.T) {
	mock, e, _ := newMockEstateWith(t, 100, func(o *scmock.Options) { o.MaxTimeReached = true }, nil)
	md, err := run(t, e, "cmd-r", mockPayload("1", "10.30.0.0/30"))
	if err != nil {
		t.Fatal(err)
	}
	if defs := mock.ScanDefinitions(); len(defs) != 0 || md["rollover_scans_deleted"] != 1 {
		t.Fatalf("left %v, metadata %v", defs, md)
	}
}

func TestMaxScanHours(t *testing.T) {
	for in, want := range map[int]string{0: "1", 1: "1", 1800: "1", 3600: "1", 3601: "2", 28800: "8", 86400: "24"} {
		if got := maxScanHours(in); got != want {
			t.Fatalf("%d s: %s, want %s", in, got, want)
		}
	}
}

// HTTP 400 for key problems (API key authorization guide).

func TestClient_400KeyProblems(t *testing.T) {
	for msg, want := range map[string]error{
		"Invalid API keys":                         ErrCredentialsRejected,
		"API key authentication is disabled":       ErrCredentialsRejected,
		"The user is locked":                       ErrCredentialsRejected,
		"Insufficient permissions for the request": ErrForbidden,
	} {
		f := newFakeSC(t)
		var calls atomic.Int32
		f.setIntercept(func(w http.ResponseWriter, r *http.Request, _ int) bool {
			calls.Add(1)
			writeError(w, 400, 74, msg)
			return true
		})
		_, err := f.client(t, f.instance(), nil).System(context.Background())
		if !errors.Is(err, want) || calls.Load() != 1 {
			t.Fatalf("%q: err %v after %d calls, want %v once", msg, err, calls.Load(), want)
		}
	}
	f := newFakeSC(t)
	var calls atomic.Int32
	f.setIntercept(func(w http.ResponseWriter, r *http.Request, _ int) bool {
		if calls.Add(1) == 1 {
			writeError(w, 400, 74, "Database error while recognizing the API key")
			return true
		}
		return false
	})
	if _, err := f.client(t, f.instance(), nil).System(context.Background()); err != nil || calls.Load() != 2 {
		t.Fatalf("database error not resubmitted: %v after %d", err, calls.Load())
	}
	f = newFakeSC(t)
	f.setIntercept(func(w http.ResponseWriter, r *http.Request, _ int) bool {
		writeError(w, 400, 146, "Invalid repository definition")
		return true
	})
	_, err := f.client(t, f.instance(), nil).System(context.Background())
	var ae *APIError
	if !errors.As(err, &ae) || errors.Is(err, ErrForbidden) || errors.Is(err, ErrCredentialsRejected) {
		t.Fatalf("other 400: %v", err)
	}
}

// Defence in depth behind the repository filter.

func TestSync_DropsRowsOfOtherRepositories(t *testing.T) {
	f := newFakeSC(t) // ignores filters: returns repositories 5 and 7
	in := f.instance()
	in.Allow.Repositories = []int{5}
	p := &fakePusher{}
	res, err := testExecutor(f, in, p).Execute(context.Background(), syncCmd(t, platformPayload(ModeFull)))
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range p.reports {
		for _, a := range r.Assets {
			if a.Properties["tenable_repository_id"] == "7" {
				t.Fatalf("pushed an asset of repository 7: %+v", a)
			}
		}
	}
	skipped, _ := res.Metadata["skipped"].(map[string]int)
	if skipped["other_repository"] == 0 {
		t.Fatalf("dropped rows not counted: %v", res.Metadata["skipped"])
	}
}
