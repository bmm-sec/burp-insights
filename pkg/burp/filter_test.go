package burp

import (
	"net/http"
	"testing"
	"time"
)

func sampleHTTPEntry() HTTPEntry {
	return HTTPEntry{
		ID:            1,
		Timestamp:     time.Date(2024, 5, 10, 12, 30, 0, 0, time.UTC),
		Host:          "example.com",
		Port:          443,
		Protocol:      "HTTP/1.1",
		Method:        "GET",
		Path:          "/api/v1/resource",
		QueryString:   "a=1&b=two",
		URL:           "https://example.com/api/v1/resource?a=1&b=two",
		StatusCode:    200,
		ContentLength: 2048,
		MIMEType:      "application/json",
		ToolSource:    ToolProxy,
		Request: &HTTPMessage{
			Raw:       []byte("GET /api/v1/resource?a=1&b=two HTTP/1.1\r\nHost: example.com\r\nX-Needle: yes\r\n\r\nreqbody"),
			Headers:   http.Header{"Host": {"example.com"}, "X-Needle": {"yes"}},
			Body:      []byte("reqbody"),
			StartLine: "GET /api/v1/resource?a=1&b=two HTTP/1.1",
		},
		Response: &HTTPMessage{
			Raw:       []byte("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nX-Resp: yep\r\n\r\nrespbody"),
			Headers:   http.Header{"Content-Type": {"application/json"}, "X-Resp": {"yep"}},
			Body:      []byte("respbody"),
			StartLine: "HTTP/1.1 200 OK",
		},
	}
}

func TestFilterMatchBasics(t *testing.T) {
	entry := sampleHTTPEntry()

	if !NewFilter().WithHost("^example").Match(entry) {
		t.Fatal("expected host filter to match")
	}
	if NewFilter().WithHost("nomatch").Match(entry) {
		t.Fatal("expected host filter to reject")
	}

	if !NewFilter().WithPath("/api/v1").Match(entry) {
		t.Fatal("expected path filter to match")
	}
	if NewFilter().WithPath("/admin").Match(entry) {
		t.Fatal("expected path filter to reject")
	}

	if !NewFilter().WithURL("example.com/api").Match(entry) {
		t.Fatal("expected URL filter to match")
	}

	if !NewFilter().WithStatusCode(200).Match(entry) {
		t.Fatal("expected status code filter to match")
	}
	if NewFilter().WithStatusCode(404).Match(entry) {
		t.Fatal("expected status code filter to reject")
	}

	if !NewFilter().WithStatusCodeRange(200, 299).Match(entry) {
		t.Fatal("expected status code range filter to match")
	}
	if NewFilter().WithStatusCodeRange(400, 499).Match(entry) {
		t.Fatal("expected status code range filter to reject")
	}

	if !NewFilter().WithContentType("json").Match(entry) {
		t.Fatal("expected content type filter to match")
	}
	if NewFilter().WithContentType("xml").Match(entry) {
		t.Fatal("expected content type filter to reject")
	}

	if !NewFilter().WithMethod("get").Match(entry) {
		t.Fatal("expected method filter to match")
	}
	if NewFilter().WithMethod("post").Match(entry) {
		t.Fatal("expected method filter to reject")
	}
}

func TestFilterMatchRangesAndContent(t *testing.T) {
	entry := sampleHTTPEntry()

	if !NewFilter().WithSizeRange(1024, 4096).Match(entry) {
		t.Fatal("expected size range to match")
	}
	if NewFilter().WithMinSize(4096).Match(entry) {
		t.Fatal("expected min size to reject")
	}
	if NewFilter().WithMaxSize(100).Match(entry) {
		t.Fatal("expected max size to reject")
	}

	from := entry.Timestamp.Add(-time.Minute)
	to := entry.Timestamp.Add(time.Minute)
	if !NewFilter().WithTimeRange(from, to).Match(entry) {
		t.Fatal("expected time range to match")
	}
	if NewFilter().WithTimeFrom(entry.Timestamp.Add(time.Minute)).Match(entry) {
		t.Fatal("expected time from to reject")
	}
	if NewFilter().WithTimeTo(entry.Timestamp.Add(-time.Minute)).Match(entry) {
		t.Fatal("expected time to to reject")
	}

	if !NewFilter().WithResponse(true).Match(entry) {
		t.Fatal("expected has response to match")
	}
	if NewFilter().WithResponse(false).Match(entry) {
		t.Fatal("expected has response false to reject")
	}

	if !NewFilter().WithTool(ToolProxy).Match(entry) {
		t.Fatal("expected tool filter to match")
	}
	if NewFilter().WithTool(ToolRepeater).Match(entry) {
		t.Fatal("expected tool filter to reject")
	}

	if !NewFilter().WithContentContains("respbody").Match(entry) {
		t.Fatal("expected content contains to match response")
	}
	if NewFilter().WithContentContains("missing").Match(entry) {
		t.Fatal("expected content contains to reject")
	}

	if !NewFilter().WithHeaderContains("X-Needle").Match(entry) {
		t.Fatal("expected header contains to match")
	}
	if !NewFilter().WithHeaderContains("yep").Match(entry) {
		t.Fatal("expected header contains to match value")
	}
	if NewFilter().WithHeaderContains("nope").Match(entry) {
		t.Fatal("expected header contains to reject")
	}

	if !NewFilter().WithBodyContains("reqbody").Match(entry) {
		t.Fatal("expected body contains to match request")
	}
	if !NewFilter().WithBodyContains("respbody").Match(entry) {
		t.Fatal("expected body contains to match response")
	}
	if NewFilter().WithBodyContains("missing").Match(entry) {
		t.Fatal("expected body contains to reject")
	}
}

func TestFilterHTTPHistory(t *testing.T) {
	entry := sampleHTTPEntry()
	entries := []HTTPEntry{entry}

	if got := FilterHTTPHistory(entries, nil); len(got) != 1 {
		t.Fatalf("expected nil filter to return all entries, got %d", len(got))
	}

	f := NewFilter().WithStatusCode(404)
	if got := FilterHTTPHistory(entries, f); len(got) != 0 {
		t.Fatalf("expected filter to return 0 entries, got %d", len(got))
	}
}

func TestParseStatusCodes(t *testing.T) {
	codes, minCode, maxCode := ParseStatusCodes("200,301-399,500")
	if len(codes) != 2 || codes[0] != 200 || codes[1] != 500 {
		t.Fatalf("unexpected codes: %#v", codes)
	}
	if minCode != 301 || maxCode != 399 {
		t.Fatalf("unexpected range: %d-%d", minCode, maxCode)
	}

	codes, minCode, maxCode = ParseStatusCodes("abc,400-")
	if len(codes) != 0 || minCode != 0 || maxCode != 0 {
		t.Fatalf("expected empty parse, got codes=%v range=%d-%d", codes, minCode, maxCode)
	}
}
