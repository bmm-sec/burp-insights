package burp

import (
	"encoding/binary"
	"net/http"
	"reflect"
	"testing"
)

func TestParseIntFromString(t *testing.T) {
	var n int
	ok, err := parseIntFromString("123abc", &n)
	if err != nil || !ok || n != 123 {
		t.Fatalf("expected 123 ok, got n=%d ok=%v err=%v", n, ok, err)
	}

	ok, err = parseIntFromString("abc", &n)
	if err != nil || ok || n != 0 {
		t.Fatalf("expected 0 false, got n=%d ok=%v err=%v", n, ok, err)
	}
}

func TestExtractContentLength(t *testing.T) {
	headers := "Content-Type: text/plain\r\nContent-Length: 5\r\n"
	if got := extractContentLength(headers); got != 5 {
		t.Fatalf("expected 5, got %d", got)
	}
}

func TestFindHTTPRequestEnd(t *testing.T) {
	data := []byte("GET / HTTP/1.1\r\nContent-Length: 4\r\n\r\nBODY")
	if got := findHTTPRequestEnd(data); got != len(data) {
		t.Fatalf("expected end at %d, got %d", len(data), got)
	}

	data = []byte("GET / HTTP/1.1\n\n")
	if got := findHTTPRequestEnd(data); got != len(data) {
		t.Fatalf("expected end at %d, got %d", len(data), got)
	}
}

func TestFindHTTPResponseEnd(t *testing.T) {
	data := []byte("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHELLO")
	if got := findHTTPResponseEnd(data); got != len(data) {
		t.Fatalf("expected end at %d, got %d", len(data), got)
	}

	data = []byte("HTTP/1.1 200 OK\r\n\r\nhelloGET /next HTTP/1.1\r\n")
	want := len("HTTP/1.1 200 OK\r\n\r\n") + len("hello")
	if got := findHTTPResponseEnd(data); got != want {
		t.Fatalf("expected end at %d, got %d", want, got)
	}
}

func TestParseHTTPMessage(t *testing.T) {
	raw := []byte("GET /path HTTP/1.1\r\nHost: example.com\r\nX-Test: one\r\nX-Test: two\r\n\r\nBODY")
	msg := parseHTTPMessage(raw)
	if msg.StartLine != "GET /path HTTP/1.1" {
		t.Fatalf("unexpected start line: %q", msg.StartLine)
	}
	if got := msg.Headers["Host"]; len(got) != 1 || got[0] != "example.com" {
		t.Fatalf("unexpected headers: %#v", msg.Headers)
	}
	if string(msg.Body) != "BODY" {
		t.Fatalf("unexpected body: %q", string(msg.Body))
	}
}

func TestParseRequestAndStatusLine(t *testing.T) {
	entry := &HTTPEntry{}
	parseRequestLine(entry, "GET /path?x=1 HTTP/1.1")
	if entry.Method != "GET" || entry.Path != "/path" || entry.QueryString != "x=1" || entry.Protocol != "HTTP/1.1" {
		t.Fatalf("unexpected request parse: %#v", entry)
	}

	entry = &HTTPEntry{}
	parseStatusLine(entry, "HTTP/1.1 404 Not Found")
	if entry.StatusCode != 404 {
		t.Fatalf("expected 404, got %d", entry.StatusCode)
	}
}

func TestExtractHostAndContentType(t *testing.T) {
	entry := &HTTPEntry{}
	headers := http.Header{"Host": {"example.com:8080"}, "Content-Type": {"text/html; charset=utf-8"}, "Content-Length": {"12"}}
	extractHostFromHeaders(entry, headers)
	extractContentTypeFromHeaders(entry, headers)
	if entry.Host != "example.com" || entry.Port != 8080 {
		t.Fatalf("unexpected host parse: host=%q port=%d", entry.Host, entry.Port)
	}
	if entry.MIMEType != "text/html" {
		t.Fatalf("unexpected mime type: %q", entry.MIMEType)
	}
	if entry.ContentLength != 12 {
		t.Fatalf("unexpected content length: %d", entry.ContentLength)
	}
}

func TestBuildURL(t *testing.T) {
	entry := &HTTPEntry{Host: "example.com", Port: 443, Path: "/path", QueryString: "a=1"}
	buildURL(entry)
	if entry.URL != "https://example.com/path?a=1" {
		t.Fatalf("unexpected url: %q", entry.URL)
	}

	entry = &HTTPEntry{Host: "example.com", Port: 8080, Path: "/path"}
	buildURL(entry)
	if entry.URL != "http://example.com:8080/path" {
		t.Fatalf("unexpected url: %q", entry.URL)
	}

	entry = &HTTPEntry{}
	buildURL(entry)
	if entry.URL != "" {
		t.Fatalf("expected empty url, got %q", entry.URL)
	}
}

func TestIntToString(t *testing.T) {
	if got := intToString(0); got != "0" {
		t.Fatalf("expected 0, got %q", got)
	}
	if got := intToString(12345); got != "12345" {
		t.Fatalf("expected 12345, got %q", got)
	}
}

func TestDeduplicateOffsets(t *testing.T) {
	input := []int64{1, 2, 2, 3, 1}
	got := deduplicateOffsets(input)
	want := []int64{1, 2, 3}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected dedup result: %#v", got)
	}
}

func TestMatchesPattern(t *testing.T) {
	if !matchesPattern([]byte{1, 2, 3}, []byte{1, 2}) {
		t.Fatal("expected pattern to match")
	}
	if matchesPattern([]byte{1, 2}, []byte{1, 2, 3}) {
		t.Fatal("expected pattern to not match")
	}
}

func TestExtractFixedUTF16BEString(t *testing.T) {
	word := "Test"
	encoded := make([]byte, 0, len(word)*2+2)
	for _, r := range word {
		buf := make([]byte, 2)
		binary.BigEndian.PutUint16(buf, uint16(r))
		encoded = append(encoded, buf...)
	}
	encoded = append(encoded, 0x00, 0x00)
	if got := extractFixedUTF16BEString(encoded, 10); got != word {
		t.Fatalf("expected %q, got %q", word, got)
	}
}
