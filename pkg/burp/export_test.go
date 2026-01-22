package burp

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func sampleExportEntry() HTTPEntry {
	entry := sampleHTTPEntry()
	entry.Timestamp = time.Date(2024, 6, 1, 10, 0, 0, 0, time.UTC)
	entry.Protocol = "HTTP/1.1"
	entry.Port = 443
	entry.MIMEType = "application/octet-stream"
	entry.Request.Body = []byte("request-body-12345")
	entry.Response.Body = []byte("response-body-12345")
	entry.ContentLength = int64(len(entry.Response.Body))
	entry.URL = "https://example.com/api/v1/resource?a=1&b=two"
	return entry
}

func TestExportJSON(t *testing.T) {
	entry := sampleExportEntry()
	var buf bytes.Buffer
	opts := DefaultExportOptions()
	if err := Export(&buf, []HTTPEntry{entry}, opts); err != nil {
		t.Fatalf("export json failed: %v", err)
	}

	var decoded []ExportedEntry
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("failed to decode json: %v", err)
	}
	if len(decoded) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(decoded))
	}
	if decoded[0].URL != entry.URL {
		t.Fatalf("unexpected url: %q", decoded[0].URL)
	}
}

func TestExportJSONLines(t *testing.T) {
	entry := sampleExportEntry()
	var buf bytes.Buffer
	opts := DefaultExportOptions()
	opts.Format = FormatJSONLines
	if err := Export(&buf, []HTTPEntry{entry, entry}, opts); err != nil {
		t.Fatalf("export jsonl failed: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d", len(lines))
	}
}

func TestExportCSV(t *testing.T) {
	entry := sampleExportEntry()
	entry.Host = "example,inc"
	entry.Path = "/path,with,comma"
	entry.Timestamp = time.Time{}
	var buf bytes.Buffer
	opts := DefaultExportOptions()
	opts.Format = FormatCSV
	if err := Export(&buf, []HTTPEntry{entry}, opts); err != nil {
		t.Fatalf("export csv failed: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "id,timestamp,method") {
		t.Fatalf("expected csv header, got %q", out)
	}
	if !strings.Contains(out, "\"example,inc\"") {
		t.Fatalf("expected escaped host, got %q", out)
	}
	if strings.Contains(out, "0001-01-01T00:00:00Z") {
		t.Fatalf("expected zero timestamp to be blank, got %q", out)
	}
}

func TestExportHARBinaryEncoding(t *testing.T) {
	entry := sampleExportEntry()
	var buf bytes.Buffer
	opts := DefaultExportOptions()
	opts.Format = FormatHAR
	if err := Export(&buf, []HTTPEntry{entry}, opts); err != nil {
		t.Fatalf("export har failed: %v", err)
	}

	var log HARLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("failed to decode har: %v", err)
	}
	if len(log.Log.Entries) != 1 {
		t.Fatalf("expected 1 har entry, got %d", len(log.Log.Entries))
	}

	content := log.Log.Entries[0].Response.Content
	if content.Encoding != "base64" {
		t.Fatalf("expected base64 encoding, got %q", content.Encoding)
	}
	decoded, err := base64.StdEncoding.DecodeString(content.Text)
	if err != nil {
		t.Fatalf("failed to decode base64: %v", err)
	}
	if string(decoded) == "" {
		t.Fatalf("expected decoded content")
	}
}

func TestConvertMessage(t *testing.T) {
	entry := sampleExportEntry()
	msg := entry.Request
	opts := DefaultExportOptions()
	opts.MaxBodySize = 4
	opts.IncludeRaw = true
	converted := convertMessage(msg, opts)
	if converted.Body != "requ" {
		t.Fatalf("expected truncated body, got %q", converted.Body)
	}
	if converted.Raw == "" {
		t.Fatalf("expected raw to be included")
	}
}

func TestParseQueryString(t *testing.T) {
	params := parseQueryString("a=1&b=two&c")
	if params["a"] != "1" || params["b"] != "two" || params["c"] != "" {
		t.Fatalf("unexpected query params: %#v", params)
	}
}

func TestGetStatusTextAndBinaryContent(t *testing.T) {
	if got := getStatusText(404); got != "Not Found" {
		t.Fatalf("unexpected status text: %q", got)
	}
	if got := getStatusText(999); got != "Unknown" {
		t.Fatalf("unexpected status text: %q", got)
	}

	if isBinaryContent("text/plain") {
		t.Fatalf("expected text/plain to be non-binary")
	}
	if isBinaryContent("application/json") {
		t.Fatalf("expected json to be non-binary")
	}
	if !isBinaryContent("application/octet-stream") {
		t.Fatalf("expected octet-stream to be binary")
	}
}

func TestCsvEscape(t *testing.T) {
	if got := csvEscape("simple"); got != "simple" {
		t.Fatalf("unexpected escape: %q", got)
	}
	if got := csvEscape("a,b"); got != "\"a,b\"" {
		t.Fatalf("unexpected escape: %q", got)
	}
	if got := csvEscape("a\"b"); got != "\"a\"\"b\"" {
		t.Fatalf("unexpected escape: %q", got)
	}
}
