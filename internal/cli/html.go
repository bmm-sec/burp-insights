package cli

import (
	"fmt"
	"html"
	"io"
	"sort"
	"time"

	"github.com/bmm-sec/burp-insights/pkg/burp"
)

func generateHTMLReport(w io.Writer, project *burp.Project, title string, includeBodies bool) error {
	stats := calculateStats(project.HTTPHistory)

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
        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
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
        .section-content { padding: 20px; }
        table { width: 100%%; border-collapse: collapse; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid var(--border); }
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
        footer {
            text-align: center;
            padding: 30px;
            color: #6b7280;
            font-size: 0.875rem;
        }
        .expandable { cursor: pointer; }
        .expandable:hover { background: #f3f4f6; }
        .details { display: none; padding: 15px; background: #f9fafb; }
        .details.show { display: block; }
        .details pre {
            background: #1f2937;
            color: #e5e7eb;
            padding: 15px;
            border-radius: 6px;
            overflow-x: auto;
            font-size: 0.8rem;
            max-height: 300px;
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
`, html.EscapeString(title), html.EscapeString(title), time.Now().Format("January 2, 2006 at 3:04 PM"))

	fmt.Fprintf(w, `
        <div class="stats-grid">
            <div class="stat-card">
                <h3>Total Requests</h3>
                <div class="value">%d</div>
            </div>
            <div class="stat-card">
                <h3>Unique Hosts</h3>
                <div class="value">%d</div>
            </div>
            <div class="stat-card">
                <h3>Success Rate</h3>
                <div class="value">%.1f%%</div>
            </div>
            <div class="stat-card">
                <h3>Error Rate</h3>
                <div class="value">%.1f%%</div>
            </div>
        </div>
`, stats.TotalRequests, stats.UniqueHosts, stats.SuccessRate, stats.ErrorRate)

	fmt.Fprint(w, `
        <div class="section">
            <div class="section-header">Hosts Overview</div>
            <div class="section-content">
                <ul class="host-list">
`)

	sortedHosts := sortMapByValue(stats.HostCounts)
	for _, kv := range sortedHosts {
		fmt.Fprintf(w, `                    <li><span class="host-name">%s</span> <span class="host-count">(%d requests)</span></li>
`, html.EscapeString(kv.Key), kv.Value)
	}

	fmt.Fprint(w, `                </ul>
            </div>
        </div>
`)

	fmt.Fprintf(w, `
        <div class="section">
            <div class="section-header">HTTP Methods</div>
            <div class="section-content">
                <table>
                    <tr>
`)

	for method, count := range stats.MethodCounts {
		pct := float64(count) / float64(stats.TotalRequests) * 100
		fmt.Fprintf(w, `                        <td><span class="method method-%s">%s</span> %d (%.1f%%)</td>
`, method, method, count, pct)
	}

	fmt.Fprint(w, `                    </tr>
                </table>
            </div>
        </div>
`)

	fmt.Fprint(w, `
        <div class="section">
            <div class="section-header">HTTP History</div>
            <div class="section-content">
                <div class="filter-bar">
                    <input type="text" id="filterInput" placeholder="Filter by URL, host, or method..." onkeyup="filterTable()">
                    <select id="statusFilter" onchange="filterTable()">
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

	maxEntries := 500
	if len(project.HTTPHistory) < maxEntries {
		maxEntries = len(project.HTTPHistory)
	}

	for i := 0; i < maxEntries; i++ {
		entry := project.HTTPHistory[i]
		methodClass := "method-" + entry.Method
		statusClass := getStatusClass(entry.StatusCode)
		size := formatSizeShort(entry.ContentLength)

		fmt.Fprintf(w, `                        <tr class="expandable" onclick="toggleDetails(%d)">
                            <td>%d</td>
                            <td><span class="method %s">%s</span></td>
                            <td class="truncate">%s</td>
                            <td class="truncate">%s</td>
                            <td><span class="status %s">%d</span></td>
                            <td>%s</td>
                        </tr>
`,
			entry.ID, entry.ID,
			methodClass, entry.Method,
			html.EscapeString(entry.Host),
			html.EscapeString(entry.Path),
			statusClass, entry.StatusCode,
			size)

		if includeBodies {
			fmt.Fprintf(w, `                        <tr>
                            <td colspan="6">
                                <div id="details-%d" class="details">
                                    <h4>Request</h4>
                                    <pre>%s</pre>
`, entry.ID, formatRequestPreview(entry))

			if entry.Response != nil {
				fmt.Fprintf(w, `                                    <h4 style="margin-top:15px">Response</h4>
                                    <pre>%s</pre>
`, formatResponsePreview(entry))
			}

			fmt.Fprint(w, `                                </div>
                            </td>
                        </tr>
`)
		}
	}

	if len(project.HTTPHistory) > maxEntries {
		fmt.Fprintf(w, `                        <tr>
                            <td colspan="6" style="text-align:center;color:#6b7280">
                                Showing %d of %d entries. Export to JSON for complete data.
                            </td>
                        </tr>
`, maxEntries, len(project.HTTPHistory))
	}

	fmt.Fprint(w, `                    </tbody>
                </table>
            </div>
        </div>
`)

	fmt.Fprintf(w, `
    </div>
    <footer>
        <p>Generated by burp-insights | %s | %d requests analyzed</p>
    </footer>
    <script>
        function filterTable() {
            const filter = document.getElementById('filterInput').value.toLowerCase();
            const statusFilter = document.getElementById('statusFilter').value;
            const rows = document.querySelectorAll('#historyTable tbody tr.expandable');

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

        function toggleDetails(id) {
            const details = document.getElementById('details-' + id);
            if (details) {
                details.classList.toggle('show');
            }
        }
    </script>
</body>
</html>
`, time.Now().Format("2006-01-02"), len(project.HTTPHistory))

	return nil
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
		stats.HostCounts[entry.Host]++
		stats.MethodCounts[entry.Method]++
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

func formatRequestPreview(entry burp.HTTPEntry) string {
	if entry.Request == nil || entry.Request.Raw == nil {
		return entry.Method + " " + entry.Path + " " + entry.Protocol
	}

	raw := string(entry.Request.Raw)
	if len(raw) > 2000 {
		raw = raw[:2000] + "\n... (truncated)"
	}
	return html.EscapeString(raw)
}

func formatResponsePreview(entry burp.HTTPEntry) string {
	if entry.Response == nil || entry.Response.Raw == nil {
		return "No response"
	}

	raw := string(entry.Response.Raw)
	if len(raw) > 2000 {
		raw = raw[:2000] + "\n... (truncated)"
	}
	return html.EscapeString(raw)
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
