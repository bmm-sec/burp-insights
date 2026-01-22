package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/bmm-sec/burp-insights/pkg/burp"
)

func TestOutputJSON(t *testing.T) {
	var buf bytes.Buffer
	data := map[string]string{"hello": "world"}
	if err := outputJSON(&buf, data); err != nil {
		t.Fatalf("outputJSON: %v", err)
	}

	var decoded map[string]string
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("decode json: %v", err)
	}
	if decoded["hello"] != "world" {
		t.Fatalf("unexpected decoded data: %#v", decoded)
	}
}

func TestOutputTable(t *testing.T) {
	var buf bytes.Buffer
	if err := outputTable(&buf, nil); err != nil {
		t.Fatalf("outputTable: %v", err)
	}
	if !strings.Contains(buf.String(), "No entries found") {
		t.Fatalf("expected no entries message, got %q", buf.String())
	}

	buf.Reset()
	entries := []burp.HTTPEntry{{ID: 1, Method: "GET", Host: "example.com", Path: "/", StatusCode: 200, ContentLength: 1024}}
	if err := outputTable(&buf, entries); err != nil {
		t.Fatalf("outputTable: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "Total: 1 entries") {
		t.Fatalf("expected total count, got %q", out)
	}
}

func TestTruncateString(t *testing.T) {
	if got := truncateString("short", 10); got != "short" {
		t.Fatalf("unexpected truncate: %q", got)
	}
	if got := truncateString("longer", 3); got != "lon" {
		t.Fatalf("unexpected truncate: %q", got)
	}
	if got := truncateString("longer", 4); got != "l..." {
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

func TestTableWriter(t *testing.T) {
	var buf bytes.Buffer
	cols := []TableColumn{{Header: "NAME", Width: 5}, {Header: "VALUE", Width: 5}}
	tw := NewTableWriter(&buf, cols)
	tw.WriteHeader()
	tw.WriteRow("alpha", "beta")

	out := buf.String()
	if !strings.Contains(out, "NAME") || !strings.Contains(out, "alpha") {
		t.Fatalf("unexpected table output: %q", out)
	}
}
