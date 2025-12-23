package cli

import (
	"fmt"
	"strings"

	"github.com/bmm-sec/burp-insights/pkg/burp"
)

type ReportSections struct {
	History  bool
	Issues   bool
	Repeater bool
	Tasks    bool
	Sitemap  bool
}

type ReportOptions struct {
	Title            string
	IncludeBodies    bool
	IncludeEvidence  bool
	MaxBodySize      int
	MaxHistory       int
	MaxIssues        int
	MaxRepeater      int
	MaxTasks         int
	MaxEvidenceItems int
	Sections         ReportSections
}

type ReportData struct {
	History      []burp.HTTPEntry
	SiteMap      *burp.SiteMap
	Issues       []burp.ScannerIssueMeta
	RepeaterTabs []string
	Tasks        []burp.UITask
}

func parseReportSections(raw string) (ReportSections, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.EqualFold(raw, "all") {
		return ReportSections{
			History:  true,
			Issues:   true,
			Repeater: true,
			Tasks:    true,
			Sitemap:  true,
		}, nil
	}

	var sections ReportSections
	for _, part := range strings.Split(raw, ",") {
		item := strings.TrimSpace(part)
		switch item {
		case "history":
			sections.History = true
		case "issues":
			sections.Issues = true
		case "repeater":
			sections.Repeater = true
		case "tasks":
			sections.Tasks = true
		case "sitemap":
			sections.Sitemap = true
		case "":
			continue
		default:
			return ReportSections{}, fmt.Errorf("unknown report section: %s", item)
		}
	}

	return sections, nil
}

func buildSiteMapFromHistory(entries []burp.HTTPEntry) *burp.SiteMap {
	siteMap := &burp.SiteMap{
		Root: make(map[string]*burp.SiteMapNode),
	}

	for i := range entries {
		entry := &entries[i]
		if entry.Host == "" {
			continue
		}

		hostNode, ok := siteMap.Root[entry.Host]
		if !ok {
			hostNode = &burp.SiteMapNode{
				Host:     entry.Host,
				Path:     "/",
				Children: make(map[string]*burp.SiteMapNode),
			}
			siteMap.Root[entry.Host] = hostNode
		}

		path := entry.Path
		if path == "" || path == "/" {
			hostNode.Entries = append(hostNode.Entries, entry)
			continue
		}

		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}

		segments := strings.Split(strings.Trim(path, "/"), "/")
		if len(segments) == 0 {
			hostNode.Entries = append(hostNode.Entries, entry)
			continue
		}

		current := hostNode
		currentPath := ""
		for idx, segment := range segments {
			if segment == "" {
				continue
			}

			currentPath += "/" + segment
			child, exists := current.Children[segment]
			if !exists {
				child = &burp.SiteMapNode{
					Host:     entry.Host,
					Path:     currentPath,
					Children: make(map[string]*burp.SiteMapNode),
				}
				current.Children[segment] = child
			}

			if idx == len(segments)-1 {
				child.Entries = append(child.Entries, entry)
			}

			current = child
		}
	}

	return siteMap
}
