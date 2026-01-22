package report

import (
	"testing"

	"github.com/bmm-sec/burp-insights/pkg/burp"
)

func TestParseSections(t *testing.T) {
	sections, err := ParseSections("all")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !sections.History || !sections.Issues || !sections.Repeater || !sections.Tasks || !sections.Sitemap {
		t.Fatalf("expected all sections, got %#v", sections)
	}

	sections, err = ParseSections("history,issues")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !sections.History || !sections.Issues || sections.Repeater || sections.Tasks || sections.Sitemap {
		t.Fatalf("unexpected sections: %#v", sections)
	}

	if _, err := ParseSections("unknown"); err == nil {
		t.Fatal("expected error for unknown section")
	}
}

func TestBuildSiteMapFromHistory(t *testing.T) {
	entries := []burp.HTTPEntry{
		{Host: "example.com", Path: "/"},
		{Host: "example.com", Path: "/api/v1/users"},
		{Host: "example.com", Path: "status"},
		{Host: "other.com", Path: "/"},
	}

	sm := BuildSiteMapFromHistory(entries)
	if sm == nil || len(sm.Root) != 2 {
		t.Fatalf("expected 2 hosts in sitemap, got %#v", sm)
	}

	root := sm.Root["example.com"]
	if root == nil {
		t.Fatal("expected example.com root")
	}

	if _, ok := root.Children["api"]; !ok {
		t.Fatal("expected api child")
	}
	if _, ok := root.Children["status"]; !ok {
		t.Fatal("expected status child")
	}
}
