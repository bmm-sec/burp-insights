package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/bmm-sec/burp-insights/pkg/burp"
)

func outputJSON(w io.Writer, data interface{}) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(data)
}

func outputTable(w io.Writer, entries []burp.HTTPEntry) error {
	if len(entries) == 0 {
		fmt.Fprintln(w, "No entries found")
		return nil
	}

	idWidth := 8
	methodWidth := 7
	statusWidth := 6
	hostWidth := 30
	pathWidth := 50
	sizeWidth := 10

	header := fmt.Sprintf("%-*s %-*s %-*s %-*s %-*s %-*s",
		idWidth, "ID",
		methodWidth, "METHOD",
		statusWidth, "STATUS",
		hostWidth, "HOST",
		pathWidth, "PATH",
		sizeWidth, "SIZE")
	fmt.Fprintln(w, header)
	fmt.Fprintln(w, strings.Repeat("-", len(header)+10))

	for _, entry := range entries {
		host := truncateString(entry.Host, hostWidth)
		path := truncateString(entry.Path, pathWidth)
		size := formatSizeShort(entry.ContentLength)

		statusStr := "-"
		if entry.StatusCode > 0 {
			statusStr = fmt.Sprintf("%d", entry.StatusCode)
		}

		fmt.Fprintf(w, "%-*d %-*s %-*s %-*s %-*s %-*s\n",
			idWidth, entry.ID,
			methodWidth, entry.Method,
			statusWidth, statusStr,
			hostWidth, host,
			pathWidth, path,
			sizeWidth, size)
	}

	fmt.Fprintf(w, "\nTotal: %d entries\n", len(entries))
	return nil
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}

func formatSizeShort(bytes int64) string {
	if bytes == 0 {
		return "-"
	}
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%dB", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

type TableColumn struct {
	Header string
	Width  int
	Align  string
}

type TableWriter struct {
	w       io.Writer
	columns []TableColumn
}

func NewTableWriter(w io.Writer, columns []TableColumn) *TableWriter {
	return &TableWriter{
		w:       w,
		columns: columns,
	}
}

func (tw *TableWriter) WriteHeader() {
	var parts []string
	for _, col := range tw.columns {
		format := fmt.Sprintf("%%-%ds", col.Width)
		parts = append(parts, fmt.Sprintf(format, col.Header))
	}
	fmt.Fprintln(tw.w, strings.Join(parts, " "))

	totalWidth := 0
	for _, col := range tw.columns {
		totalWidth += col.Width + 1
	}
	fmt.Fprintln(tw.w, strings.Repeat("-", totalWidth))
}

func (tw *TableWriter) WriteRow(values ...string) {
	var parts []string
	for i, col := range tw.columns {
		if i >= len(values) {
			break
		}
		value := truncateString(values[i], col.Width)
		format := fmt.Sprintf("%%-%ds", col.Width)
		parts = append(parts, fmt.Sprintf(format, value))
	}
	fmt.Fprintln(tw.w, strings.Join(parts, " "))
}
