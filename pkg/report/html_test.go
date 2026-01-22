package report

import (
	"bytes"
	"math"
	"net/http"
	"os"
	"testing"

	"github.com/bmm-sec/burp-insights/pkg/burp"
)

func sampleReportEntry() burp.HTTPEntry {
	return burp.HTTPEntry{
		ID:            1,
		Host:          "example.com",
		Path:          "/api",
		Protocol:      "HTTP/1.1",
		Method:        "GET",
		StatusCode:    200,
		ContentLength: 2048,
		Request: &burp.HTTPMessage{
			Raw:     []byte("GET /api HTTP/1.1\r\nHost: example.com\r\n\r\nbody"),
			Headers: http.Header{"Host": {"example.com"}},
			Body:    []byte("body"),
		},
		Response: &burp.HTTPMessage{
			Raw:     []byte("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nresp"),
			Headers: http.Header{"Content-Type": {"text/plain"}},
			Body:    []byte("resp"),
		},
	}
}

func TestCalculateStats(t *testing.T) {
	entries := []burp.HTTPEntry{
		{Host: "a", Method: "GET", StatusCode: 200},
		{Host: "b", Method: "POST", StatusCode: 500},
		{Host: "a", Method: "GET", StatusCode: 302},
	}

	stats := calculateStats(entries)
	if stats.TotalRequests != 3 || stats.UniqueHosts != 2 {
		t.Fatalf("unexpected counts: %#v", stats)
	}
	if math.Abs(stats.SuccessRate-66.666) > 0.2 {
		t.Fatalf("unexpected success rate: %f", stats.SuccessRate)
	}
	if math.Abs(stats.ErrorRate-33.333) > 0.2 {
		t.Fatalf("unexpected error rate: %f", stats.ErrorRate)
	}
}

func TestSeverityAndConfidenceBadges(t *testing.T) {
	if severityBadgeClass(burp.SeverityHigh) != "badge-error" {
		t.Fatal("expected high severity badge")
	}
	if confidenceBadgeClass(burp.ConfidenceFirm) != "badge-firm" {
		t.Fatal("expected firm confidence badge")
	}
}

func TestSortAndGroupIssues(t *testing.T) {
	issues := []burp.ScannerIssueMeta{
		{Type: 2, Severity: burp.SeverityLow, Confidence: burp.ConfidenceFirm, SerialNumber: 2, Definition: &burp.IssueDefinition{Name: "B"}},
		{Type: 1, Severity: burp.SeverityHigh, Confidence: burp.ConfidenceCertain, SerialNumber: 1, Definition: &burp.IssueDefinition{Name: "A"}},
		{Type: 1, Severity: burp.SeverityMedium, Confidence: burp.ConfidenceCertain, SerialNumber: 3, Definition: &burp.IssueDefinition{Name: "A"}},
	}

	sorted := sortIssuesForReport(issues)
	if sorted[0].Severity != burp.SeverityHigh {
		t.Fatalf("expected high severity first")
	}

	groups := groupIssuesByType(issues)
	if len(groups) != 2 {
		t.Fatalf("expected 2 groups, got %d", len(groups))
	}
	if groups[0].MaxSeverity != burp.SeverityHigh {
		t.Fatalf("expected max severity high, got %v", groups[0].MaxSeverity)
	}
}

func TestBuildIssuesSection(t *testing.T) {
	issues := []burp.ScannerIssueMeta{
		{Type: 1, Severity: burp.SeverityLow, Confidence: burp.ConfidenceFirm, SerialNumber: 1, Definition: &burp.IssueDefinition{Name: "Alpha"}},
		{Type: 2, Severity: burp.SeverityHigh, Confidence: burp.ConfidenceCertain, SerialNumber: 2, Definition: &burp.IssueDefinition{Name: "Beta"}},
	}
	opts := Options{MaxIssues: 1}
	section := buildIssuesSection(issues, opts)
	if section.Total != 2 || len(section.Groups) == 0 {
		t.Fatalf("unexpected issues section: %#v", section)
	}
	if section.MaxNotice == "" {
		t.Fatalf("expected max notice")
	}
}

func TestBuildHistorySection(t *testing.T) {
	entry := sampleReportEntry()
	opts := Options{IncludeBodies: true, MaxHistory: 1}
	section := buildHistorySection([]burp.HTTPEntry{entry, entry}, opts)
	if section.Total != 2 || len(section.Entries) != 1 {
		t.Fatalf("unexpected history section: %#v", section)
	}
	if !section.IncludeBodies || !section.Entries[0].Expandable {
		t.Fatalf("expected bodies to be included")
	}
}

func TestSiteMapHelpers(t *testing.T) {
	entry := sampleReportEntry()
	entry.Protocol = "https"
		node := &burp.SiteMapNode{Host: "example.com", Path: "/", Entries: []*burp.HTTPEntry{&entry}, Children: map[string]*burp.SiteMapNode{}}
	if proto := selectSiteMapProtocol(node); proto != "https" {
		t.Fatalf("expected https protocol, got %q", proto)
	}
	if count := countSiteMapEntries(node); count != 1 {
		t.Fatalf("expected 1 entry, got %d", count)
	}

	view := buildSiteMapNode("example.com", "example.com", node)
	if view.CopyValue != "https://example.com/" {
		t.Fatalf("unexpected copy value: %q", view.CopyValue)
	}
}

func TestFormatPreviewsAndTruncate(t *testing.T) {
	entry := sampleReportEntry()
	if got := formatRequestPreview(entry, 5); got == "" {
		t.Fatal("expected request preview")
	}
	if got := formatResponsePreview(entry, 5); got == "" {
		t.Fatal("expected response preview")
	}

	msg := &burp.ExportedMessage{StartLine: "GET / HTTP/1.1", Headers: map[string]string{"Host": "example.com"}, Body: "body", Raw: "RAW"}
	if got := formatExportedMessagePreview(msg, false, 100); got == "RAW" {
		t.Fatal("expected header-based preview when bodies excluded")
	}

	if got := truncateReportString("hello", 3); got != "hel\n... (truncated)" {
		t.Fatalf("unexpected truncate: %q", got)
	}
}

func TestFormatSizeShort(t *testing.T) {
	if got := formatSizeShort(0); got != "-" {
		t.Fatalf("expected '-', got %q", got)
	}
	if got := formatSizeShort(1024); got != "1.0KB" {
		t.Fatalf("unexpected size: %q", got)
	}
}

func TestGenerateHTML(t *testing.T) {
	entry := sampleReportEntry()
	report := &Data{History: []burp.HTTPEntry{entry}}
	opts := Options{Sections: Sections{History: true}}
	var buf bytes.Buffer
	if err := GenerateHTML(&buf, report, opts); err != nil {
		t.Fatalf("GenerateHTML: %v", err)
	}
	if !bytes.Contains(buf.Bytes(), []byte("Burp Project Report")) {
		t.Fatalf("expected default title in report output")
	}

	custom := "Custom Title"
	tmpFile, err := os.CreateTemp(t.TempDir(), "tmpl-*.html")
	if err != nil {
		t.Fatalf("create template: %v", err)
	}
	if _, err := tmpFile.WriteString("{{.Title}}"); err != nil {
		t.Fatalf("write template: %v", err)
	}
	if err := tmpFile.Close(); err != nil {
		t.Fatalf("close template: %v", err)
	}

	opts.Title = custom
	opts.TemplatePath = tmpFile.Name()
	buf.Reset()
	if err := GenerateHTML(&buf, report, opts); err != nil {
		t.Fatalf("GenerateHTML with template: %v", err)
	}
	if buf.String() != custom {
		t.Fatalf("expected custom template output %q, got %q", custom, buf.String())
	}
}
