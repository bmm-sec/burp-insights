package cli

import (
	"fmt"
	"html"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/bmm-sec/burp-insights/pkg/burp"
)

func generateHTMLReport(w io.Writer, report *ReportData, opts ReportOptions) error {
	stats := Stats{}
	if opts.Sections.History && len(report.History) > 0 {
		stats = calculateStats(report.History)
	}

	fmt.Fprintf(w, `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>%s</title>
    <style>
        :root {
            --primary: #dc2626;
            --success: #16a34a;
            --warning: #ca8a04;
            --error: #dc2626;
            --neutral: #374151;
            --bg: #f9fafb;
            --card-bg: #ffffff;
            --border: #e5e7eb;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--bg);
            color: var(--neutral);
            line-height: 1.6;
        }
        .container { width: 96vw; max-width: 96vw; margin: 0 auto; padding: 20px; }
        header {
            background: var(--primary);
            color: white;
            padding: 30px 0;
            margin-bottom: 30px;
        }
        header h1 { font-size: 2rem; font-weight: 600; }
        header p { opacity: 0.9; margin-top: 5px; }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .stat-card {
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 20px;
        }
        .stat-card h3 { font-size: 0.875rem; color: #6b7280; margin-bottom: 5px; }
        .stat-card .value { font-size: 2rem; font-weight: 700; color: #6b7280; }
        .section {
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 8px;
            margin-bottom: 30px;
        }
        .section-header {
            padding: 15px 20px;
            border-bottom: 1px solid var(--border);
            font-weight: 600;
            font-size: 1.1rem;
        }
        .section-content { padding: 20px; overflow-x: auto; }
        table { width: 100%%; border-collapse: collapse; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid var(--border); vertical-align: top; overflow-wrap: anywhere; }
        th { background: #f3f4f6; font-weight: 600; font-size: 0.875rem; }
        tr:hover { background: #f9fafb; }
        .method {
            display: inline-block;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 600;
        }
        .method-GET { background: #dbeafe; color: #1d4ed8; }
        .method-POST { background: #dcfce7; color: #15803d; }
        .method-PUT { background: #fef3c7; color: #b45309; }
        .method-DELETE { background: #fee2e2; color: #b91c1c; }
        .status { font-weight: 600; }
        .status-2xx { color: var(--success); }
        .status-3xx { color: var(--primary); }
        .status-4xx { color: var(--warning); }
        .status-5xx { color: var(--error); }
        .host-list { list-style: none; }
        .host-list li { padding: 8px 0; border-bottom: 1px solid var(--border); }
        .host-list li:last-child { border-bottom: none; }
        .host-name { font-weight: 600; }
        .host-count { color: #6b7280; font-size: 0.875rem; }
        .filter-bar {
            display: flex;
            gap: 10px;
            margin-bottom: 20px;
            flex-wrap: wrap;
        }
        .filter-bar input, .filter-bar select {
            padding: 8px 12px;
            border: 1px solid var(--border);
            border-radius: 6px;
            font-size: 0.875rem;
        }
        .filter-bar input { flex: 1; min-width: 200px; }
        .truncate { max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .badge {
            display: inline-block;
            padding: 2px 8px;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 500;
        }
        .badge-info { background: #dbeafe; color: #1d4ed8; }
        .badge-success { background: #dcfce7; color: #15803d; }
        .badge-warning { background: #fef3c7; color: #b45309; }
        .badge-error { background: #fee2e2; color: #b91c1c; }
        .badge-tentative { background: #fef3c7; color: #b45309; }
        .badge-firm { background: #dbeafe; color: #1d4ed8; }
        .badge-certain { background: #dcfce7; color: #15803d; }
        .badge-neutral { background: #e5e7eb; color: #374151; }
        footer {
            text-align: center;
            padding: 30px;
            color: #6b7280;
            font-size: 0.875rem;
        }
        .expandable { cursor: pointer; }
        .expandable:hover { background: #f3f4f6; }
        .details { display: none; padding: 15px; background: #f9fafb; overflow-x: auto; }
        .details.show { display: block; }
        .details a, .details .meta-item, .details li { overflow-wrap: anywhere; word-break: break-word; }
        .details pre {
            background: #1f2937;
            color: #e5e7eb;
            padding: 15px;
            border-radius: 6px;
            overflow-x: auto;
            font-size: 0.8rem;
            max-height: 300px;
            max-width: 100%%;
            white-space: pre-wrap;
            word-break: break-word;
            overflow-wrap: anywhere;
        }
        .details h4 { margin: 10px 0; }
        .details h5 { margin: 10px 0; font-size: 0.9rem; }
        .details h6 { margin: 10px 0; font-size: 0.85rem; }
        .issue-header { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; margin-bottom: 12px; }
        .issue-title { flex: 1 1 100%%; font-size: 1rem; font-weight: 600; color: #111827; }
        .issue-meta { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }
        .issue-type {
            padding: 2px 8px;
            border-radius: 9999px;
            font-size: 0.75rem;
            border: 1px solid var(--border);
            background: #f3f4f6;
            color: #374151;
        }
        .detail-grid {
            display: grid;
            grid-template-columns: 130px 1fr;
            gap: 6px 12px;
            margin-bottom: 10px;
        }
        .detail-label { font-size: 0.85rem; font-weight: 600; color: #374151; }
        .detail-value { font-size: 0.85rem; color: #4b5563; overflow-wrap: anywhere; }
        @media (max-width: 900px) {
            .detail-grid { grid-template-columns: 1fr; }
        }
        .issue-group {
            border: 1px solid var(--border);
            border-radius: 8px;
            margin-bottom: 16px;
            background: var(--card-bg);
        }
        .issue-group summary {
            list-style: none;
            cursor: pointer;
            padding: 12px 40px 12px 16px;
            display: flex;
            align-items: center;
            position: relative;
        }
        .issue-group summary::-webkit-details-marker { display: none; }
        .issue-group summary::after {
            content: ">";
            font-weight: 600;
            position: absolute;
            right: 16px;
            top: 50%%;
            transform: translateY(-50%%);
        }
        .issue-group[open] summary::after { content: "v"; }
        .issue-group-summary {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 12px;
            flex-wrap: wrap;
            flex: 1;
        }
        .issue-group-title { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
        .issue-group-name { font-weight: 600; color: #111827; }
        .issue-group-meta { color: #6b7280; font-size: 0.85rem; }
        .issue-group-body { padding: 0 16px 16px; }
        .muted { color: #6b7280; font-size: 0.85rem; }
        .sitemap-tree { margin-top: 10px; }
        .tree-root, .tree-list { list-style: none; margin: 0; padding-left: 0; }
        .tree-list { margin-left: 12px; padding-left: 12px; border-left: 1px dashed var(--border); }
        .tree-node summary {
            list-style: none;
            cursor: pointer;
            display: flex;
            align-items: center;
            gap: 8px;
            padding: 4px 0;
        }
        .tree-node summary::-webkit-details-marker { display: none; }
        .tree-node summary::before {
            content: ">";
            font-size: 0.7rem;
            color: #6b7280;
            margin-right: 4px;
        }
        .tree-node[open] summary::before { content: "v"; }
        .tree-leaf {
            display: flex;
            align-items: center;
            gap: 8px;
            padding: 4px 0;
        }
        .tree-leaf::before {
            content: "-";
            color: #9ca3af;
            margin-right: 4px;
        }
        .tree-label { color: #111827; }
        .tree-count {
            margin-left: auto;
            background: #f3f4f6;
            border: 1px solid var(--border);
            border-radius: 9999px;
            padding: 2px 8px;
            font-size: 0.75rem;
            color: #6b7280;
        }
    </style>
</head>
<body>
    <header>
        <div class="container">
            <h1>%s</h1>
            <p>Generated on %s</p>
        </div>
    </header>
    <div class="container">
`, html.EscapeString(opts.Title), html.EscapeString(opts.Title), time.Now().Format("January 2, 2006 at 3:04 PM"))

	renderSummaryCards(w, report, opts, stats)

	if opts.Sections.Issues {
		renderIssuesSection(w, report.Issues, opts)
	}
	if opts.Sections.Tasks {
		renderTasksSection(w, report.Tasks, opts)
	}
	if opts.Sections.Repeater {
		renderRepeaterSection(w, report.RepeaterTabs, opts)
	}
	if opts.Sections.History {
		renderHistorySection(w, report.History, opts)
	}
	if opts.Sections.Sitemap {
		renderSitemapSection(w, report.SiteMap)
	}

	footerNote := "Generated by burp-insights"
	if opts.Sections.History {
		footerNote = fmt.Sprintf("%s | %d requests analyzed", footerNote, len(report.History))
	} else if opts.Sections.Issues {
		footerNote = fmt.Sprintf("%s | %d issues analyzed", footerNote, len(report.Issues))
	}

	fmt.Fprintf(w, `
    </div>
    <footer>
        <p>%s | %s</p>
    </footer>
    <script>
        function filterHistoryTable() {
            const table = document.getElementById('historyTable');
            if (!table) { return; }
            const filter = document.getElementById('historyFilterInput').value.toLowerCase();
            const statusFilter = document.getElementById('historyStatusFilter').value;
            const rows = table.querySelectorAll('tbody tr.expandable');

            rows.forEach(row => {
                const text = row.textContent.toLowerCase();
                const status = row.querySelector('.status')?.textContent || '';
                const matchesText = filter === '' || text.includes(filter);
                const matchesStatus = statusFilter === '' || status.startsWith(statusFilter);
                row.style.display = matchesText && matchesStatus ? '' : 'none';

                const nextRow = row.nextElementSibling;
                if (nextRow && !nextRow.classList.contains('expandable')) {
                    nextRow.style.display = matchesText && matchesStatus ? '' : 'none';
                }
            });
        }

        function filterIssuesTable() {
            const container = document.getElementById('issuesTable');
            if (!container) { return; }
            const filter = document.getElementById('issueFilterInput').value.toLowerCase();
            const severityFilter = document.getElementById('issueSeverityFilter')?.value || '';
            const confidenceFilter = document.getElementById('issueConfidenceFilter')?.value || '';
            const typeFilter = document.getElementById('issueTypeFilter')?.value || '';
            const rows = container.querySelectorAll('tr.issue-row');
            const filtersActive = filter !== '' || severityFilter !== '' || confidenceFilter !== '' || typeFilter !== '';

            rows.forEach(row => {
                const search = row.dataset.search || row.textContent.toLowerCase();
                const matchesText = filter === '' || search.includes(filter);
                const matchesSeverity = severityFilter === '' || row.dataset.severity === severityFilter;
                const matchesConfidence = confidenceFilter === '' || row.dataset.confidence === confidenceFilter;
                const matchesType = typeFilter === '' || row.dataset.type === typeFilter;
                const matches = matchesText && matchesSeverity && matchesConfidence && matchesType;
                row.style.display = matches ? '' : 'none';

                const nextRow = row.nextElementSibling;
                if (nextRow && !nextRow.classList.contains('issue-row')) {
                    nextRow.style.display = matches ? '' : 'none';
                }
            });

            const groups = container.querySelectorAll('details.issue-group');
            groups.forEach(group => {
                const groupRows = group.querySelectorAll('tr.issue-row');
                let anyVisible = false;
                groupRows.forEach(row => {
                    if (row.style.display !== 'none') {
                        anyVisible = true;
                    }
                });
                group.style.display = anyVisible ? '' : 'none';
                if (anyVisible && filtersActive) {
                    group.open = true;
                }
            });
        }

        function toggleDetails(id) {
            const details = document.getElementById('details-' + id);
            if (details) {
                details.classList.toggle('show');
            }
        }
    </script>
</body>
</html>
`, html.EscapeString(footerNote), time.Now().Format("2006-01-02"))

	return nil
}

func renderSummaryCards(w io.Writer, report *ReportData, opts ReportOptions, stats Stats) {
	type card struct {
		Title string
		Value string
	}

	var cards []card
	if opts.Sections.History {
		cards = append(cards, card{Title: "Total Requests", Value: fmt.Sprintf("%d", stats.TotalRequests)})
		cards = append(cards, card{Title: "Unique Hosts", Value: fmt.Sprintf("%d", stats.UniqueHosts)})
		cards = append(cards, card{Title: "Success Rate", Value: fmt.Sprintf("%.1f%%", stats.SuccessRate)})
		cards = append(cards, card{Title: "Error Rate", Value: fmt.Sprintf("%.1f%%", stats.ErrorRate)})
	}
	if opts.Sections.Issues {
		cards = append(cards, card{Title: "Issues", Value: fmt.Sprintf("%d", len(report.Issues))})
	}
	if opts.Sections.Tasks {
		cards = append(cards, card{Title: "Tasks", Value: fmt.Sprintf("%d", len(report.Tasks))})
	}
	if opts.Sections.Repeater {
		cards = append(cards, card{Title: "Repeater Tabs", Value: fmt.Sprintf("%d", len(report.RepeaterTabs))})
	}
	if opts.Sections.Sitemap && report.SiteMap != nil {
		cards = append(cards, card{Title: "Site Map Hosts", Value: fmt.Sprintf("%d", len(report.SiteMap.Root))})
	}

	if len(cards) == 0 {
		return
	}

	fmt.Fprint(w, `
        <div class="stats-grid">
`)
	for _, c := range cards {
		fmt.Fprintf(w, `            <div class="stat-card">
                <h3>%s</h3>
                <div class="value">%s</div>
            </div>
`, html.EscapeString(c.Title), html.EscapeString(c.Value))
	}
	fmt.Fprint(w, `        </div>
`)
}

func renderIssuesSection(w io.Writer, issues []burp.ScannerIssueMeta, opts ReportOptions) {
	total := len(issues)
	sorted := sortIssuesForReport(issues)
	display := sorted
	if opts.MaxIssues > 0 && total > opts.MaxIssues {
		display = sorted[:opts.MaxIssues]
	}

	groups := groupIssuesByType(display)
	type issueTypeOption struct {
		ID    string
		Label string
	}
	var typeOptions []issueTypeOption
	for _, group := range groups {
		typeID := fmt.Sprintf("0x%08x", group.TypeID)
		label := fmt.Sprintf("%s (%s)", group.Name, typeID)
		typeOptions = append(typeOptions, issueTypeOption{
			ID:    typeID,
			Label: label,
		})
	}
	sort.Slice(typeOptions, func(i, j int) bool {
		return typeOptions[i].Label < typeOptions[j].Label
	})

	fmt.Fprintf(w, `
        <div class="section">
            <div class="section-header">Scanner Issues (%d)</div>
            <div class="section-content">
`, total)

	if total == 0 {
		fmt.Fprint(w, "                <p>No issues found.</p>\n            </div>\n        </div>\n")
		return
	}

	fmt.Fprint(w, `                <div class="filter-bar">
                    <input type="text" id="issueFilterInput" placeholder="Filter by name, host, type, or serial..." onkeyup="filterIssuesTable()">
                    <select id="issueSeverityFilter" onchange="filterIssuesTable()">
                        <option value="">All Severities</option>
                        <option value="High">High</option>
                        <option value="Medium">Medium</option>
                        <option value="Low">Low</option>
                        <option value="Information">Information</option>
                    </select>
                    <select id="issueConfidenceFilter" onchange="filterIssuesTable()">
                        <option value="">All Confidence</option>
                        <option value="Certain">Certain</option>
                        <option value="Firm">Firm</option>
                        <option value="Tentative">Tentative</option>
                    </select>
                    <select id="issueTypeFilter" onchange="filterIssuesTable()">
                        <option value="">All Issue Types</option>
`)
	for _, option := range typeOptions {
		fmt.Fprintf(w, "                        <option value=\"%s\">%s</option>\n", html.EscapeString(option.ID), html.EscapeString(option.Label))
	}
	fmt.Fprint(w, `                    </select>
                </div>
                <div id="issuesTable">
`)

	for _, group := range groups {
		typeID := fmt.Sprintf("0x%08x", group.TypeID)
		groupSevClass := severityBadgeClass(group.MaxSeverity)
		fmt.Fprintf(w, `                    <details class="issue-group" data-type="%s">
                        <summary>
                            <div class="issue-group-summary">
                                <div class="issue-group-title">
                                    <span class="badge %s">%s</span>
                                    <span class="issue-group-name">%s</span>
                                </div>
                                <div class="issue-group-meta">Type %s - %d instance(s)</div>
                            </div>
                        </summary>
                        <div class="issue-group-body">
                            <table class="issue-table">
                                <thead>
                                    <tr>
                                        <th>Instance</th>
                                        <th>Serial</th>
                                        <th>Severity</th>
                                        <th>Confidence</th>
                                        <th>Host</th>
                                        <th>Path</th>
                                    </tr>
                                </thead>
                                <tbody>
`, html.EscapeString(typeID), groupSevClass, html.EscapeString(group.MaxSeverity.String()), html.EscapeString(group.Name), html.EscapeString(typeID), len(group.Issues))

		for i, issue := range group.Issues {
			name := issueDisplayName(issue)
			host := issue.Host
			path := issue.Path
			if host == "" && path == "" && issue.Location != "" {
				path = issue.Location
			}
			hostLabel := host
			if hostLabel == "" {
				hostLabel = "-"
			}
			pathLabel := path
			if pathLabel == "" {
				pathLabel = "-"
			}

			sevClass := severityBadgeClass(issue.Severity)
			confClass := confidenceBadgeClass(issue.Confidence)
			detailsID := fmt.Sprintf("issue-%d", issue.SerialNumber)
			search := strings.ToLower(fmt.Sprintf("%s %s %s %s %s %d %d", name, typeID, host, path, issue.Location, issue.SerialNumber, issue.TaskID))

			fmt.Fprintf(w, `                        <tr class="expandable issue-row" data-type="%s" data-severity="%s" data-confidence="%s" data-search="%s" onclick="toggleDetails('%s')">
                            <td>%d</td>
                            <td>%d</td>
                            <td><span class="badge %s">%s</span></td>
                            <td><span class="badge %s">%s</span></td>
                            <td class="truncate">%s</td>
                            <td class="truncate">%s</td>
                        </tr>
`, html.EscapeString(typeID), html.EscapeString(issue.Severity.String()), html.EscapeString(issue.Confidence.String()), html.EscapeString(search), detailsID, i+1, issue.SerialNumber, sevClass, html.EscapeString(issue.Severity.String()), confClass, html.EscapeString(issue.Confidence.String()), html.EscapeString(hostLabel), html.EscapeString(pathLabel))

			location := issue.Location
			if location == "" {
				location = "-"
			}

			fmt.Fprintf(w, `                        <tr>
                            <td colspan="6">
                                <div id="details-%s" class="details">
                                    <div class="issue-header">
                                        <div class="issue-title">%s</div>
                                        <div class="issue-meta">
                                            <span class="badge %s">%s</span>
                                            <span class="badge %s">%s</span>
                                            <span class="issue-type">Type %s</span>
                                        </div>
                                    </div>
                                    <div class="detail-grid">
                                        <div class="detail-label">Task ID</div>
                                        <div class="detail-value">%d</div>
                                        <div class="detail-label">Host</div>
                                        <div class="detail-value">%s</div>
                                        <div class="detail-label">Path</div>
                                        <div class="detail-value">%s</div>
                                        <div class="detail-label">Location</div>
                                        <div class="detail-value">%s</div>
                                    </div>
`, detailsID, html.EscapeString(name), sevClass, html.EscapeString(issue.Severity.String()), confClass, html.EscapeString(issue.Confidence.String()), html.EscapeString(typeID), issue.TaskID, html.EscapeString(hostLabel), html.EscapeString(pathLabel), html.EscapeString(location))

			if issue.Definition != nil {
				if issue.Definition.Description != "" {
					fmt.Fprintf(w, "                                    <h4>Description</h4>\n                                    %s\n", issue.Definition.Description)
				}
				if issue.Definition.Remediation != "" {
					fmt.Fprintf(w, "                                    <h4>Remediation</h4>\n                                    %s\n", issue.Definition.Remediation)
				}
				if issue.Definition.WebIntro != "" {
					fmt.Fprintf(w, "                                    <h4>Overview</h4>\n                                    %s\n", issue.Definition.WebIntro)
				}
				if len(issue.Definition.References) > 0 {
					fmt.Fprint(w, "                                    <h4>References</h4>\n                                    <ul>\n")
					for _, ref := range issue.Definition.References {
						fmt.Fprintf(w, "                                        <li><a href=\"%s\" target=\"_blank\">%s</a></li>\n", html.EscapeString(ref.URL), html.EscapeString(ref.Title))
					}
					fmt.Fprint(w, "                                    </ul>\n")
				}
				if len(issue.Definition.VulnerabilityClassifications) > 0 {
					fmt.Fprint(w, "                                    <h4>Classifications</h4>\n                                    <ul>\n")
					for _, ref := range issue.Definition.VulnerabilityClassifications {
						fmt.Fprintf(w, "                                        <li><a href=\"%s\" target=\"_blank\">%s</a></li>\n", html.EscapeString(ref.URL), html.EscapeString(ref.Title))
					}
					fmt.Fprint(w, "                                    </ul>\n")
				}
			}

			if opts.IncludeEvidence && len(issue.Evidence) > 0 {
				evidence := issue.Evidence
				if opts.MaxEvidenceItems > 0 && len(evidence) > opts.MaxEvidenceItems {
					evidence = evidence[:opts.MaxEvidenceItems]
				}

				fmt.Fprint(w, "                                    <h4>Evidence</h4>\n")
				for idx, ev := range evidence {
					fmt.Fprintf(w, "                                    <h5>Evidence %d</h5>\n", idx+1)
					if ev.Request != nil {
						fmt.Fprintf(w, "                                    <h6>Request</h6>\n                                    <pre>%s</pre>\n", formatExportedMessagePreview(ev.Request, opts.IncludeBodies, opts.MaxBodySize))
					}
					if ev.Response != nil {
						fmt.Fprintf(w, "                                    <h6>Response</h6>\n                                    <pre>%s</pre>\n", formatExportedMessagePreview(ev.Response, opts.IncludeBodies, opts.MaxBodySize))
					}
				}
				if opts.MaxEvidenceItems > 0 && len(issue.Evidence) > opts.MaxEvidenceItems {
					fmt.Fprintf(w, "                                    <p>Showing %d of %d evidence item(s).</p>\n", len(evidence), len(issue.Evidence))
				}
			}

			fmt.Fprint(w, `                                </div>
                            </td>
                        </tr>
`)
		}

		fmt.Fprint(w, `                                </tbody>
                            </table>
                        </div>
                    </details>
`)
	}

	if opts.MaxIssues > 0 && total > opts.MaxIssues {
		fmt.Fprintf(w, `                    <div class="muted">Showing %d of %d issues. Increase --max-issues to include more.</div>
`, len(display), total)
	}

	fmt.Fprint(w, `                </div>
            </div>
        </div>
`)
}

func renderTasksSection(w io.Writer, tasks []burp.UITask, opts ReportOptions) {
	total := len(tasks)
	display := tasks
	if opts.MaxTasks > 0 && total > opts.MaxTasks {
		display = tasks[:opts.MaxTasks]
	}

	fmt.Fprintf(w, `
        <div class="section">
            <div class="section-header">Tasks (%d)</div>
            <div class="section-content">
`, total)

	if total == 0 {
		fmt.Fprint(w, "                <p>No tasks found.</p>\n            </div>\n        </div>\n")
		return
	}

	fmt.Fprint(w, `                <table>
                    <thead>
                        <tr>
                            <th>#</th>
                            <th>Name</th>
                            <th>Type</th>
                            <th>Scope</th>
                            <th>ID</th>
                        </tr>
                    </thead>
                    <tbody>
`)

	for i, task := range display {
		fmt.Fprintf(w, `                        <tr>
                            <td>%d</td>
                            <td>%s</td>
                            <td>%d</td>
                            <td>%s</td>
                            <td>%d</td>
                        </tr>
`, i+1, html.EscapeString(task.Name), task.Type, html.EscapeString(task.Scope), task.ID)
	}

	if opts.MaxTasks > 0 && total > opts.MaxTasks {
		fmt.Fprintf(w, `                        <tr>
                            <td colspan="5" style="text-align:center;color:#6b7280">
                                Showing %d of %d tasks. Increase --max-tasks to include more.
                            </td>
                        </tr>
`, len(display), total)
	}

	fmt.Fprint(w, `                    </tbody>
                </table>
            </div>
        </div>
`)
}

func renderRepeaterSection(w io.Writer, tabs []string, opts ReportOptions) {
	total := len(tabs)
	display := tabs
	if opts.MaxRepeater > 0 && total > opts.MaxRepeater {
		display = tabs[:opts.MaxRepeater]
	}

	fmt.Fprintf(w, `
        <div class="section">
            <div class="section-header">Repeater Tabs (%d)</div>
            <div class="section-content">
`, total)

	if total == 0 {
		fmt.Fprint(w, "                <p>No Repeater tabs found.</p>\n            </div>\n        </div>\n")
		return
	}

	fmt.Fprint(w, "                <ul class=\"host-list\">\n")
	for _, tab := range display {
		fmt.Fprintf(w, "                    <li><span class=\"host-name\">%s</span></li>\n", html.EscapeString(tab))
	}
	fmt.Fprint(w, "                </ul>\n")

	if opts.MaxRepeater > 0 && total > opts.MaxRepeater {
		fmt.Fprintf(w, "                <p style=\"color:#6b7280\">Showing %d of %d tabs. Increase --max-repeater to include more.</p>\n", len(display), total)
	}

	fmt.Fprint(w, "            </div>\n        </div>\n")
}

func renderHistorySection(w io.Writer, entries []burp.HTTPEntry, opts ReportOptions) {
	total := len(entries)
	display := entries
	if opts.MaxHistory > 0 && total > opts.MaxHistory {
		display = entries[:opts.MaxHistory]
	}

	fmt.Fprintf(w, `
        <div class="section">
            <div class="section-header">HTTP History (%d)</div>
            <div class="section-content">
`, total)

	if total == 0 {
		fmt.Fprint(w, "                <p>No HTTP history found.</p>\n            </div>\n        </div>\n")
		return
	}

	fmt.Fprint(w, `                <div class="filter-bar">
                    <input type="text" id="historyFilterInput" placeholder="Filter by URL, host, or method..." onkeyup="filterHistoryTable()">
                    <select id="historyStatusFilter" onchange="filterHistoryTable()">
                        <option value="">All Status</option>
                        <option value="2">2xx Success</option>
                        <option value="3">3xx Redirect</option>
                        <option value="4">4xx Client Error</option>
                        <option value="5">5xx Server Error</option>
                    </select>
                </div>
                <table id="historyTable">
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>Method</th>
                            <th>Host</th>
                            <th>Path</th>
                            <th>Status</th>
                            <th>Size</th>
                        </tr>
                    </thead>
                    <tbody>
`)

	for _, entry := range display {
		methodClass := "method-" + entry.Method
		statusClass := getStatusClass(entry.StatusCode)
		size := formatSizeShort(entry.ContentLength)
		rowClass := ""
		if opts.IncludeBodies {
			rowClass = "expandable"
		}

		fmt.Fprintf(w, `                        <tr class="%s"`, rowClass)
		if opts.IncludeBodies {
			fmt.Fprintf(w, ` onclick="toggleDetails('history-%d')"`, entry.ID)
		}
		fmt.Fprintf(w, `>
                            <td>%d</td>
                            <td><span class="method %s">%s</span></td>
                            <td class="truncate">%s</td>
                            <td class="truncate">%s</td>
                            <td><span class="status %s">%d</span></td>
                            <td>%s</td>
                        </tr>
`, entry.ID, methodClass, html.EscapeString(entry.Method), html.EscapeString(entry.Host), html.EscapeString(entry.Path), statusClass, entry.StatusCode, size)

		if opts.IncludeBodies {
			fmt.Fprintf(w, `                        <tr>
                            <td colspan="6">
                                <div id="details-history-%d" class="details">
                                    <h4>Request</h4>
                                    <pre>%s</pre>
`, entry.ID, formatRequestPreview(entry, opts.MaxBodySize))

			if entry.Response != nil {
				fmt.Fprintf(w, `                                    <h4 style="margin-top:15px">Response</h4>
                                    <pre>%s</pre>
`, formatResponsePreview(entry, opts.MaxBodySize))
			}

			fmt.Fprint(w, `                                </div>
                            </td>
                        </tr>
`)
		}
	}

	if opts.MaxHistory > 0 && total > opts.MaxHistory {
		fmt.Fprintf(w, `                        <tr>
                            <td colspan="6" style="text-align:center;color:#6b7280">
                                Showing %d of %d entries. Increase --max-history to include more.
                            </td>
                        </tr>
`, len(display), total)
	}

	fmt.Fprint(w, `                    </tbody>
                </table>
            </div>
        </div>
`)
}

func renderSitemapSection(w io.Writer, siteMap *burp.SiteMap) {
	fmt.Fprint(w, `
        <div class="section">
            <div class="section-header">Site Map</div>
            <div class="section-content">
`)

	if siteMap == nil || len(siteMap.Root) == 0 {
		fmt.Fprint(w, "                <p>No site map data available.</p>\n            </div>\n        </div>\n")
		return
	}

	hosts := make([]string, 0, len(siteMap.Root))
	for host := range siteMap.Root {
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)

	fmt.Fprint(w, "                <div class=\"sitemap-tree\">\n                    <ul class=\"tree-root\">\n")
	for _, host := range hosts {
		node := siteMap.Root[host]
		renderSiteMapTreeNode(w, host, node, false)
	}
	fmt.Fprint(w, "                    </ul>\n                </div>\n            </div>\n        </div>\n")
}

func renderSiteMapTreeNode(w io.Writer, label string, node *burp.SiteMapNode, open bool) {
	if node == nil {
		return
	}

	count := countSiteMapEntries(node)
	if len(node.Children) == 0 {
		fmt.Fprintf(w, "                        <li><div class=\"tree-leaf\"><span class=\"tree-label\">%s</span><span class=\"tree-count\">%d</span></div></li>\n", html.EscapeString(label), count)
		return
	}

	openAttr := ""
	if open {
		openAttr = " open"
	}

	fmt.Fprintf(w, "                        <li><details class=\"tree-node\"%s><summary><span class=\"tree-label\">%s</span><span class=\"tree-count\">%d</span></summary>\n", openAttr, html.EscapeString(label), count)
	fmt.Fprint(w, "                            <ul class=\"tree-list\">\n")

	keys := make([]string, 0, len(node.Children))
	for key := range node.Children {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		renderSiteMapTreeNode(w, key, node.Children[key], false)
	}

	fmt.Fprint(w, "                            </ul>\n                        </details></li>\n")
}

func countSiteMapEntries(node *burp.SiteMapNode) int {
	if node == nil {
		return 0
	}

	total := len(node.Entries)
	for _, child := range node.Children {
		total += countSiteMapEntries(child)
	}
	return total
}

func severityBadgeClass(sev burp.Severity) string {
	switch sev {
	case burp.SeverityInfo:
		return "badge-info"
	case burp.SeverityLow:
		return "badge-warning"
	case burp.SeverityMedium:
		return "badge-warning"
	case burp.SeverityHigh:
		return "badge-error"
	default:
		return "badge-info"
	}
}

func confidenceBadgeClass(conf burp.Confidence) string {
	switch conf {
	case burp.ConfidenceTentative:
		return "badge-tentative"
	case burp.ConfidenceFirm:
		return "badge-firm"
	case burp.ConfidenceCertain:
		return "badge-certain"
	default:
		return "badge-neutral"
	}
}

const unknownIssueName = "Unknown"

type issueGroup struct {
	TypeID      uint32
	Name        string
	Issues      []burp.ScannerIssueMeta
	MaxSeverity burp.Severity
}

func issueDisplayName(issue burp.ScannerIssueMeta) string {
	if issue.Definition != nil && issue.Definition.Name != "" {
		return issue.Definition.Name
	}
	return unknownIssueName
}

func severitySortValue(sev burp.Severity) int {
	switch sev {
	case burp.SeverityHigh:
		return 3
	case burp.SeverityMedium:
		return 2
	case burp.SeverityLow:
		return 1
	case burp.SeverityInfo:
		return 0
	default:
		return -1
	}
}

func confidenceSortValue(conf burp.Confidence) int {
	switch conf {
	case burp.ConfidenceCertain:
		return 2
	case burp.ConfidenceFirm:
		return 1
	case burp.ConfidenceTentative:
		return 0
	default:
		return -1
	}
}

func sortIssuesForReport(issues []burp.ScannerIssueMeta) []burp.ScannerIssueMeta {
	sorted := append([]burp.ScannerIssueMeta(nil), issues...)
	sort.SliceStable(sorted, func(i, j int) bool {
		severityI := severitySortValue(sorted[i].Severity)
		severityJ := severitySortValue(sorted[j].Severity)
		if severityI != severityJ {
			return severityI > severityJ
		}
		confidenceI := confidenceSortValue(sorted[i].Confidence)
		confidenceJ := confidenceSortValue(sorted[j].Confidence)
		if confidenceI != confidenceJ {
			return confidenceI > confidenceJ
		}
		nameI := issueDisplayName(sorted[i])
		nameJ := issueDisplayName(sorted[j])
		if nameI != nameJ {
			return nameI < nameJ
		}
		return sorted[i].SerialNumber < sorted[j].SerialNumber
	})
	return sorted
}

func groupIssuesByType(issues []burp.ScannerIssueMeta) []issueGroup {
	groups := make(map[uint32]*issueGroup)
	for _, issue := range issues {
		group, ok := groups[issue.Type]
		if !ok {
			group = &issueGroup{
				TypeID:      issue.Type,
				MaxSeverity: issue.Severity,
			}
			groups[issue.Type] = group
		}

		name := issueDisplayName(issue)
		if name != unknownIssueName {
			group.Name = name
		} else if group.Name == "" {
			group.Name = name
		}

		if severitySortValue(issue.Severity) > severitySortValue(group.MaxSeverity) {
			group.MaxSeverity = issue.Severity
		}
		group.Issues = append(group.Issues, issue)
	}

	var grouped []issueGroup
	for _, group := range groups {
		if group.Name == "" {
			group.Name = unknownIssueName
		}

		sort.SliceStable(group.Issues, func(i, j int) bool {
			severityI := severitySortValue(group.Issues[i].Severity)
			severityJ := severitySortValue(group.Issues[j].Severity)
			if severityI != severityJ {
				return severityI > severityJ
			}
			confidenceI := confidenceSortValue(group.Issues[i].Confidence)
			confidenceJ := confidenceSortValue(group.Issues[j].Confidence)
			if confidenceI != confidenceJ {
				return confidenceI > confidenceJ
			}
			return group.Issues[i].SerialNumber < group.Issues[j].SerialNumber
		})

		grouped = append(grouped, *group)
	}

	sort.SliceStable(grouped, func(i, j int) bool {
		severityI := severitySortValue(grouped[i].MaxSeverity)
		severityJ := severitySortValue(grouped[j].MaxSeverity)
		if severityI != severityJ {
			return severityI > severityJ
		}
		if grouped[i].Name != grouped[j].Name {
			return grouped[i].Name < grouped[j].Name
		}
		return grouped[i].TypeID < grouped[j].TypeID
	})

	return grouped
}

type Stats struct {
	TotalRequests int
	UniqueHosts   int
	SuccessRate   float64
	ErrorRate     float64
	HostCounts    map[string]int
	MethodCounts  map[string]int
	StatusCounts  map[int]int
}

func calculateStats(entries []burp.HTTPEntry) Stats {
	stats := Stats{
		TotalRequests: len(entries),
		HostCounts:    make(map[string]int),
		MethodCounts:  make(map[string]int),
		StatusCounts:  make(map[int]int),
	}

	successCount := 0
	errorCount := 0

	for _, entry := range entries {
		stats.MethodCounts[entry.Method]++
		stats.HostCounts[entry.Host]++
		stats.StatusCounts[entry.StatusCode]++

		if entry.StatusCode >= 200 && entry.StatusCode < 400 {
			successCount++
		} else if entry.StatusCode >= 400 {
			errorCount++
		}
	}

	stats.UniqueHosts = len(stats.HostCounts)
	if stats.TotalRequests > 0 {
		stats.SuccessRate = float64(successCount) / float64(stats.TotalRequests) * 100
		stats.ErrorRate = float64(errorCount) / float64(stats.TotalRequests) * 100
	}

	return stats
}

func getStatusClass(code int) string {
	switch {
	case code >= 200 && code < 300:
		return "status-2xx"
	case code >= 300 && code < 400:
		return "status-3xx"
	case code >= 400 && code < 500:
		return "status-4xx"
	case code >= 500:
		return "status-5xx"
	default:
		return ""
	}
}

func formatRequestPreview(entry burp.HTTPEntry, maxBodySize int) string {
	if entry.Request == nil || entry.Request.Raw == nil {
		return entry.Method + " " + entry.Path + " " + entry.Protocol
	}

	raw := string(entry.Request.Raw)
	raw = truncateReportString(raw, maxBodySize)
	return html.EscapeString(raw)
}

func formatResponsePreview(entry burp.HTTPEntry, maxBodySize int) string {
	if entry.Response == nil || entry.Response.Raw == nil {
		return "No response"
	}

	raw := string(entry.Response.Raw)
	raw = truncateReportString(raw, maxBodySize)
	return html.EscapeString(raw)
}

func formatExportedMessagePreview(msg *burp.ExportedMessage, includeBodies bool, maxBodySize int) string {
	if msg == nil {
		return "No data"
	}

	raw := ""
	if includeBodies && msg.Raw != "" {
		raw = msg.Raw
	} else {
		var b strings.Builder
		if msg.StartLine != "" {
			b.WriteString(msg.StartLine)
			b.WriteString("\n")
		}
		for key, value := range msg.Headers {
			b.WriteString(key)
			b.WriteString(": ")
			b.WriteString(value)
			b.WriteString("\n")
		}
		if includeBodies && msg.Body != "" {
			b.WriteString("\n")
			b.WriteString(msg.Body)
		}
		raw = b.String()
	}

	raw = truncateReportString(raw, maxBodySize)
	return html.EscapeString(raw)
}

func truncateReportString(s string, maxLen int) string {
	if maxLen <= 0 || len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "\n... (truncated)"
}

type KeyValue struct {
	Key   string
	Value int
}

func sortMapByValue(m map[string]int) []KeyValue {
	var kvs []KeyValue
	for k, v := range m {
		kvs = append(kvs, KeyValue{k, v})
	}
	sort.Slice(kvs, func(i, j int) bool {
		return kvs[i].Value > kvs[j].Value
	})
	return kvs
}
