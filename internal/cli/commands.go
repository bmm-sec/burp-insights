package cli

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/bmm-sec/burp-insights/pkg/burp"
	"github.com/spf13/cobra"
)

var (
	outputFile   string
	outputFormat string
	noColor      bool
	verbose      bool
	quiet        bool

	hostFilter        string
	pathFilter        string
	methodFilter      string
	statusFilter      string
	contentTypeFilter string
	fromTime          string
	toTime            string
	minSize           int64
	maxSize           int64
	limit             int
	includeBody       bool
	maxBodySize       int64

	searchQuery      string
	searchRegex      bool
	searchIgnoreCase bool
	searchScope      string

	reportTitle    string
	reportTemplate string

	burpJarPath string

	reportSections        string
	reportMaxHistory      int
	reportMaxIssues       int
	reportMaxRepeater     int
	reportMaxTasks        int
	reportMaxEvidence     int
	reportIncludeEvidence bool

	issueDefsUseEmbedded bool
	burpNoAutoDetect     bool
)

var rootCmd = &cobra.Command{
	Use:   "burp-insights",
	Short: "Parse and analyze Burp Suite project files",
	Long: `burp-insights is a CLI tool for parsing and analyzing Burp Suite project files.
It extracts HTTP history, site maps, scanner findings, and more from .burp files.`,
}

var infoCmd = &cobra.Command{
	Use:   "info <file.burp>",
	Short: "Display project metadata and statistics",
	Args:  cobra.ExactArgs(1),
	RunE:  runInfo,
}

var historyCmd = &cobra.Command{
	Use:   "history <file.burp>",
	Short: "List HTTP history entries",
	Args:  cobra.ExactArgs(1),
	RunE:  runHistory,
}

var searchCmd = &cobra.Command{
	Use:   "search <file.burp>",
	Short: "Search across all content",
	Args:  cobra.ExactArgs(1),
	RunE:  runSearch,
}

var exportCmd = &cobra.Command{
	Use:   "export <file.burp>",
	Short: "Export data in various formats",
	Args:  cobra.ExactArgs(1),
	RunE:  runExport,
}

var reportCmd = &cobra.Command{
	Use:   "report <file.burp>",
	Short: "Generate HTML report",
	Args:  cobra.ExactArgs(1),
	RunE:  runReport,
}

var sitemapCmd = &cobra.Command{
	Use:   "sitemap <file.burp>",
	Short: "Show site map tree",
	Args:  cobra.ExactArgs(1),
	RunE:  runSitemap,
}

var repeaterCmd = &cobra.Command{
	Use:   "repeater <file.burp>",
	Short: "List Repeater tab names",
	Args:  cobra.ExactArgs(1),
	RunE:  runRepeater,
}

var issuesCmd = &cobra.Command{
	Use:   "issues <file.burp>",
	Short: "List Scanner issues found in the project",
	Args:  cobra.ExactArgs(1),
	RunE:  runIssues,
}

var tasksCmd = &cobra.Command{
	Use:   "tasks <file.burp>",
	Short: "List Burp tasks (UI task list)",
	Args:  cobra.ExactArgs(1),
	RunE:  runTasks,
}

var issueDefinitionsCmd = &cobra.Command{
	Use:   "issue-definitions",
	Short: "Export Burp Scanner issue definitions as JSON",
	Args:  cobra.NoArgs,
	RunE:  runIssueDefinitions,
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&outputFile, "output", "o", "", "Write output to file")
	rootCmd.PersistentFlags().StringVarP(&outputFormat, "format", "f", "table", "Output format: json, jsonl, csv, table, har")
	rootCmd.PersistentFlags().BoolVar(&noColor, "no-color", false, "Disable colored output")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")
	rootCmd.PersistentFlags().BoolVar(&quiet, "quiet", false, "Suppress non-essential output")

	historyCmd.Flags().StringVarP(&hostFilter, "host", "H", "", "Filter by host (regex)")
	historyCmd.Flags().StringVarP(&pathFilter, "path", "p", "", "Filter by path (regex)")
	historyCmd.Flags().StringVarP(&methodFilter, "method", "m", "", "Filter by HTTP method (comma-separated)")
	historyCmd.Flags().StringVarP(&statusFilter, "status", "s", "", "Filter by status code (e.g., 200,301-399,500)")
	historyCmd.Flags().StringVarP(&contentTypeFilter, "content-type", "t", "", "Filter by content type")
	historyCmd.Flags().StringVar(&fromTime, "from", "", "Filter from timestamp (RFC3339)")
	historyCmd.Flags().StringVar(&toTime, "to", "", "Filter to timestamp (RFC3339)")
	historyCmd.Flags().Int64Var(&minSize, "min-size", 0, "Minimum response size")
	historyCmd.Flags().Int64Var(&maxSize, "max-size", 0, "Maximum response size")
	historyCmd.Flags().IntVarP(&limit, "limit", "n", 0, "Limit number of results")
	historyCmd.Flags().BoolVar(&includeBody, "include-body", false, "Include request/response bodies")
	historyCmd.Flags().Int64Var(&maxBodySize, "body-size", 10240, "Max body size to include")

	searchCmd.Flags().StringVarP(&searchQuery, "query", "q", "", "Search query")
	searchCmd.Flags().BoolVarP(&searchRegex, "regex", "r", false, "Treat query as regex")
	searchCmd.Flags().BoolVarP(&searchIgnoreCase, "ignore-case", "i", true, "Case-insensitive search")
	searchCmd.Flags().StringVar(&searchScope, "scope", "all", "Search scope: all, requests, responses, headers, bodies, urls")
	searchCmd.Flags().IntVarP(&limit, "limit", "n", 0, "Limit number of results")

	issuesCmd.Flags().StringVar(&burpJarPath, "burp-jar", "", "Optional Burp Suite JAR path to override embedded issue definitions")
	issuesCmd.Flags().BoolVar(&burpNoAutoDetect, "no-jar-autodetect", false, "Disable auto-detection of Burp Suite jar for issue definitions")

	exportCmd.Flags().StringVarP(&hostFilter, "host", "H", "", "Filter by host (regex)")
	exportCmd.Flags().StringVarP(&pathFilter, "path", "p", "", "Filter by path (regex)")
	exportCmd.Flags().StringVarP(&methodFilter, "method", "m", "", "Filter by HTTP method")
	exportCmd.Flags().StringVarP(&statusFilter, "status", "s", "", "Filter by status code")
	exportCmd.Flags().BoolVar(&includeBody, "include-body", false, "Include bodies in export")
	exportCmd.Flags().Int64Var(&maxBodySize, "body-size", 10240, "Max body size to include")

	reportCmd.Flags().StringVar(&reportTitle, "title", "Burp Project Report", "Report title")
	reportCmd.Flags().StringVar(&reportTemplate, "template", "", "Custom HTML template")
	reportCmd.Flags().BoolVar(&includeBody, "include-bodies", false, "Include request/response bodies")
	reportCmd.Flags().StringVar(&reportSections, "sections", "all", "Report sections: all, issues, history, repeater, tasks, sitemap")
	reportCmd.Flags().IntVar(&reportMaxHistory, "max-history", 500, "Max HTTP history entries to include (0 for all)")
	reportCmd.Flags().IntVar(&reportMaxIssues, "max-issues", 0, "Max issues to include (0 for all)")
	reportCmd.Flags().IntVar(&reportMaxRepeater, "max-repeater", 0, "Max repeater tabs to include (0 for all)")
	reportCmd.Flags().IntVar(&reportMaxTasks, "max-tasks", 0, "Max tasks to include (0 for all)")
	reportCmd.Flags().IntVar(&reportMaxEvidence, "max-evidence", 0, "Max evidence items per issue (0 for all)")
	reportCmd.Flags().BoolVar(&reportIncludeEvidence, "include-evidence", true, "Include issue evidence request/response data")
	reportCmd.Flags().StringVar(&burpJarPath, "burp-jar", "", "Optional Burp Suite JAR path to override embedded issue definitions")
	reportCmd.Flags().BoolVar(&burpNoAutoDetect, "no-jar-autodetect", false, "Disable auto-detection of Burp Suite jar for issue definitions")

	issueDefinitionsCmd.Flags().StringVar(&burpJarPath, "burp-jar", "", "Optional Burp Suite JAR path to override embedded issue definitions")
	issueDefinitionsCmd.Flags().BoolVar(&issueDefsUseEmbedded, "embedded", false, "Use embedded issue definitions instead of a jar")
	issueDefinitionsCmd.Flags().BoolVar(&burpNoAutoDetect, "no-jar-autodetect", false, "Disable auto-detection of Burp Suite jar for issue definitions")

	rootCmd.AddCommand(infoCmd)
	rootCmd.AddCommand(historyCmd)
	rootCmd.AddCommand(searchCmd)
	rootCmd.AddCommand(exportCmd)
	rootCmd.AddCommand(reportCmd)
	rootCmd.AddCommand(sitemapCmd)
	rootCmd.AddCommand(repeaterCmd)
	rootCmd.AddCommand(issuesCmd)
	rootCmd.AddCommand(tasksCmd)
	rootCmd.AddCommand(issueDefinitionsCmd)
}

func Execute() error {
	return rootCmd.Execute()
}

func runInfo(cmd *cobra.Command, args []string) error {
	filePath := args[0]

	if !quiet {
		fmt.Fprintf(os.Stderr, "Opening %s...\n", filePath)
	}

	reader, err := burp.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer reader.Close()

	count, err := reader.HTTPHistoryCount()
	if err != nil {
		return fmt.Errorf("failed to count records: %w", err)
	}

	meta := reader.Metadata()

	output := getOutputWriter()
	defer closeOutputWriter(output)

	if outputFormat == "json" {
		return outputJSON(output, map[string]interface{}{
			"file":         filePath,
			"file_size":    meta.FileSize,
			"record_count": count,
		})
	}

	fmt.Fprintf(output, "File: %s\n", filePath)
	fmt.Fprintf(output, "Size: %s (%d bytes)\n", formatSize(meta.FileSize), meta.FileSize)
	fmt.Fprintf(output, "HTTP Records: %d\n", count)

	if verbose {
		history, err := reader.HTTPHistory()
		if err == nil {
			hosts := make(map[string]int)
			methods := make(map[string]int)
			statusCodes := make(map[int]int)

			for _, entry := range history {
				hosts[entry.Host]++
				methods[entry.Method]++
				if entry.StatusCode > 0 {
					statusCodes[entry.StatusCode]++
				}
			}

			fmt.Fprintf(output, "\nHosts (%d unique):\n", len(hosts))
			for host, count := range hosts {
				fmt.Fprintf(output, "  %s: %d\n", host, count)
			}

			fmt.Fprintf(output, "\nMethods:\n")
			for method, count := range methods {
				fmt.Fprintf(output, "  %s: %d\n", method, count)
			}

			fmt.Fprintf(output, "\nStatus Codes:\n")
			for code, count := range statusCodes {
				fmt.Fprintf(output, "  %d: %d\n", code, count)
			}
		}
	}

	return nil
}

func runHistory(cmd *cobra.Command, args []string) error {
	filePath := args[0]

	reader, err := burp.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer reader.Close()

	history, err := reader.HTTPHistory()
	if err != nil {
		return fmt.Errorf("failed to read history: %w", err)
	}

	filter := buildFilter()
	if filter != nil {
		history = burp.FilterHTTPHistory(history, filter)
	}

	if limit > 0 && len(history) > limit {
		history = history[:limit]
	}

	output := getOutputWriter()
	defer closeOutputWriter(output)

	switch outputFormat {
	case "json":
		opts := burp.ExportOptions{
			Format:      burp.FormatJSON,
			IncludeBody: includeBody,
			PrettyPrint: true,
			MaxBodySize: maxBodySize,
		}
		return burp.Export(output, history, opts)
	case "jsonl":
		opts := burp.ExportOptions{
			Format:      burp.FormatJSONLines,
			IncludeBody: includeBody,
			MaxBodySize: maxBodySize,
		}
		return burp.Export(output, history, opts)
	case "csv":
		opts := burp.ExportOptions{
			Format: burp.FormatCSV,
		}
		return burp.Export(output, history, opts)
	case "har":
		opts := burp.ExportOptions{
			Format:      burp.FormatHAR,
			IncludeBody: includeBody,
			PrettyPrint: true,
			MaxBodySize: maxBodySize,
		}
		return burp.Export(output, history, opts)
	default:
		return outputTable(output, history)
	}
}

func runSearch(cmd *cobra.Command, args []string) error {
	if searchQuery == "" {
		return fmt.Errorf("search query is required (use -q flag)")
	}

	filePath := args[0]

	reader, err := burp.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer reader.Close()

	ctx := context.Background()
	entryChan, errChan := reader.StreamHTTPHistory(ctx)

	scope := burp.SearchAll
	switch strings.ToLower(searchScope) {
	case "requests":
		scope = burp.SearchRequests
	case "responses":
		scope = burp.SearchResponses
	case "headers":
		scope = burp.SearchHeaders
	case "bodies":
		scope = burp.SearchBodies
	case "urls":
		scope = burp.SearchURLs
	}

	opts := burp.SearchOptions{
		Query:         searchQuery,
		CaseSensitive: !searchIgnoreCase,
		Scope:         scope,
		Regex:         searchRegex,
		MaxResults:    limit,
	}

	resultChan, searchErrChan := burp.SearchStream(ctx, entryChan, opts)

	output := getOutputWriter()
	defer closeOutputWriter(output)

	var results []burp.SearchResult
	for result := range resultChan {
		results = append(results, result)
	}

	if err := <-errChan; err != nil {
		return err
	}
	if err := <-searchErrChan; err != nil {
		return err
	}

	if outputFormat == "json" {
		return outputJSON(output, results)
	}

	fmt.Fprintf(output, "Found %d results for \"%s\"\n\n", len(results), searchQuery)
	for _, result := range results {
		fmt.Fprintf(output, "[%d] %s %s\n", result.Entry.ID, result.Entry.Method, result.Entry.URL)
		fmt.Fprintf(output, "    Host: %s, Status: %d\n", result.Entry.Host, result.Entry.StatusCode)
		for _, match := range result.Matches {
			fmt.Fprintf(output, "    Match in %s: ...%s...\n", match.Location, truncate(match.Context, 80))
		}
		fmt.Fprintln(output)
	}

	return nil
}

func runExport(cmd *cobra.Command, args []string) error {
	filePath := args[0]

	reader, err := burp.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer reader.Close()

	history, err := reader.HTTPHistory()
	if err != nil {
		return fmt.Errorf("failed to read history: %w", err)
	}

	filter := buildFilter()
	if filter != nil {
		history = burp.FilterHTTPHistory(history, filter)
	}

	output := getOutputWriter()
	defer closeOutputWriter(output)

	format := burp.FormatJSON
	switch strings.ToLower(outputFormat) {
	case "jsonl":
		format = burp.FormatJSONLines
	case "csv":
		format = burp.FormatCSV
	case "har":
		format = burp.FormatHAR
	}

	opts := burp.ExportOptions{
		Format:      format,
		IncludeBody: includeBody,
		PrettyPrint: true,
		MaxBodySize: maxBodySize,
	}

	return burp.Export(output, history, opts)
}

func runReport(cmd *cobra.Command, args []string) error {
	filePath := args[0]

	sections, err := parseReportSections(reportSections)
	if err != nil {
		return err
	}
	if !sections.History && !sections.Issues && !sections.Repeater && !sections.Tasks && !sections.Sitemap {
		return fmt.Errorf("no report sections selected")
	}

	reader, err := burp.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer reader.Close()

	report := &ReportData{}
	opts := ReportOptions{
		Title:            reportTitle,
		IncludeBodies:    includeBody,
		IncludeEvidence:  reportIncludeEvidence,
		MaxBodySize:      int(maxBodySize),
		MaxHistory:       reportMaxHistory,
		MaxIssues:        reportMaxIssues,
		MaxRepeater:      reportMaxRepeater,
		MaxTasks:         reportMaxTasks,
		MaxEvidenceItems: reportMaxEvidence,
		Sections:         sections,
	}

	if sections.Issues {
		loadIssueDefinitions()
		issues, err := reader.ScannerIssueMetas()
		if err != nil {
			return fmt.Errorf("failed to extract issues: %w", err)
		}
		report.Issues = issues
	}

	if sections.Repeater {
		tabs, err := reader.RepeaterTabNames()
		if err != nil {
			return fmt.Errorf("failed to extract repeater tabs: %w", err)
		}
		report.RepeaterTabs = tabs
	}

	if sections.Tasks {
		tasks, err := reader.UITasks()
		if err != nil {
			return fmt.Errorf("failed to extract tasks: %w", err)
		}
		report.Tasks = tasks
	}

	needHistory := sections.History || sections.Sitemap
	if needHistory {
		history, err := reader.HTTPHistory()
		if err != nil {
			return fmt.Errorf("failed to read history: %w", err)
		}
		report.History = history
		if sections.Sitemap {
			report.SiteMap = buildSiteMapFromHistory(history)
		}
	}

	output := getOutputWriter()
	defer closeOutputWriter(output)

	return generateHTMLReport(output, report, opts)
}

func runSitemap(cmd *cobra.Command, args []string) error {
	filePath := args[0]

	reader, err := burp.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer reader.Close()

	project, err := reader.Project()
	if err != nil {
		return fmt.Errorf("failed to load project: %w", err)
	}

	output := getOutputWriter()
	defer closeOutputWriter(output)

	if outputFormat == "json" {
		return outputJSON(output, project.SiteMap)
	}

	fmt.Fprintln(output, "Site Map:")
	for host, node := range project.SiteMap.Root {
		fmt.Fprintf(output, "\n%s (%d entries)\n", host, len(node.Entries))

		paths := make(map[string]int)
		for _, entry := range node.Entries {
			paths[entry.Path]++
		}

		for path, count := range paths {
			fmt.Fprintf(output, "  %s (%d)\n", path, count)
		}
	}

	return nil
}

func runRepeater(cmd *cobra.Command, args []string) error {
	filePath := args[0]

	if !quiet {
		fmt.Fprintf(os.Stderr, "Scanning %s for Repeater tabs...\n", filePath)
	}

	reader, err := burp.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer reader.Close()

	tabNames, err := reader.RepeaterTabNames()
	if err != nil {
		return fmt.Errorf("failed to extract repeater tabs: %w", err)
	}

	output := getOutputWriter()
	defer closeOutputWriter(output)

	if outputFormat == "json" {
		return outputJSON(output, map[string]interface{}{
			"count": len(tabNames),
			"tabs":  tabNames,
		})
	}

	if len(tabNames) == 0 {
		fmt.Fprintln(output, "No Repeater tabs found")
		return nil
	}

	fmt.Fprintf(output, "Found %d Repeater tab(s):\n\n", len(tabNames))
	for i, name := range tabNames {
		fmt.Fprintf(output, "%3d. %s\n", i+1, name)
	}

	if !quiet {
		fmt.Fprintf(os.Stderr, "\nNote: Only tab names are extracted. Request/response data requires more complex parsing.\n")
	}

	return nil
}

func runIssues(cmd *cobra.Command, args []string) error {
	filePath := args[0]

	loadIssueDefinitions()

	reader, err := burp.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer reader.Close()

	metas, err := reader.ScannerIssueMetas()
	if err != nil {
		return fmt.Errorf("failed to extract issues: %w", err)
	}

	output := getOutputWriter()
	defer closeOutputWriter(output)

	if outputFormat == "json" {
		return outputJSON(output, map[string]interface{}{
			"burpFile": filePath,
			"count":    len(metas),
			"issues":   metas,
		})
	}

	fmt.Fprintf(output, "Found %d issue(s):\n\n", len(metas))
	fmt.Fprintf(output, "%-3s %-20s %-22s %-10s %-40s %s\n", "#", "Serial", "Severity/Confidence", "Type", "Name", "Host/Path")
	fmt.Fprintf(output, "%s\n", strings.Repeat("-", 120))
	for i, meta := range metas {
		sevConf := fmt.Sprintf("%s/%s", meta.Severity.String(), meta.Confidence.String())
		typeID := fmt.Sprintf("0x%08x", meta.Type)

		name := "Unknown"
		if meta.Definition != nil && meta.Definition.Name != "" {
			name = meta.Definition.Name
		}

		hostPath := meta.Location
		if meta.Host != "" && meta.Path != "" {
			hostPath = meta.Host + meta.Path
		} else if meta.Host != "" {
			hostPath = meta.Host
		} else if meta.Path != "" {
			hostPath = meta.Path
		}

		fmt.Fprintf(output, "%-3d %-20d %-22s %-10s %-40s %s\n",
			i+1,
			meta.SerialNumber,
			sevConf,
			typeID,
			name,
			hostPath,
		)
	}
	return nil
}

func runTasks(cmd *cobra.Command, args []string) error {
	filePath := args[0]

	reader, err := burp.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer reader.Close()

	tasks, err := reader.UITasks()
	if err != nil {
		return fmt.Errorf("failed to extract tasks: %w", err)
	}

	output := getOutputWriter()
	defer closeOutputWriter(output)

	if outputFormat == "json" {
		return outputJSON(output, map[string]interface{}{
			"burpFile": filePath,
			"count":    len(tasks),
			"tasks":    tasks,
		})
	}

	if len(tasks) == 0 {
		fmt.Fprintln(output, "No tasks found")
		return nil
	}

	fmt.Fprintf(output, "Found %d task(s):\n\n", len(tasks))
	for _, task := range tasks {
		fmt.Fprintf(output, "- %s\n", task.Name)
	}

	return nil
}

func runIssueDefinitions(cmd *cobra.Command, args []string) error {
	loaded := false

	if !issueDefsUseEmbedded {
		jarPath, autoDetected := resolveBurpJarPath()
		if jarPath != "" {
			if err := burp.LoadIssueDefinitionsFromJar(jarPath); err != nil {
				if !autoDetected {
					return fmt.Errorf("failed to load issue definitions from jar: %w", err)
				}
				if !quiet {
					fmt.Fprintf(os.Stderr, "Warning: failed to load issue definitions from %s: %v\n", jarPath, err)
				}
			} else {
				loaded = true
			}
		}
	}

	if !loaded {
		if err := burp.LoadEmbeddedIssueDefinitions(); err != nil {
			return fmt.Errorf("failed to load embedded issue definitions: %w", err)
		}
		if !issueDefsUseEmbedded && !quiet && verbose {
			fmt.Fprintln(os.Stderr, "Using embedded issue definitions (no jar provided)")
		}
	}

	defs := burp.IssueDefinitions()
	export := burp.IssueDefinitionsExport{
		Count:       len(defs),
		Definitions: defs,
	}

	output := getOutputWriter()
	defer closeOutputWriter(output)

	return outputJSON(output, export)
}

func loadIssueDefinitions() {
	if err := burp.LoadEmbeddedIssueDefinitions(); err != nil {
		if !quiet && verbose {
			fmt.Fprintf(os.Stderr, "Warning: failed to load embedded issue definitions: %v\n", err)
		}
	}

	jarPath, autoDetected := resolveBurpJarPath()
	if jarPath == "" {
		return
	}

	if err := burp.LoadIssueDefinitionsFromJar(jarPath); err != nil {
		if !quiet && (!autoDetected || verbose) {
			fmt.Fprintf(os.Stderr, "Warning: failed to load issue definitions from %s: %v\n", jarPath, err)
		}
		return
	}

	if verbose {
		fmt.Fprintf(os.Stderr, "Loaded issue definitions from %s\n", jarPath)
	}
}

func resolveBurpJarPath() (string, bool) {
	jarPath := strings.TrimSpace(burpJarPath)
	if jarPath == "" {
		jarPath = strings.TrimSpace(os.Getenv("BURP_JAR_PATH"))
	}
	if jarPath == "" {
		jarPath = strings.TrimSpace(os.Getenv("BURP_JAR"))
	}

	autoDetected := false
	if jarPath == "" && !burpNoAutoDetect {
		if detected, err := burp.FindDefaultBurpJar(); err == nil {
			jarPath = detected
			autoDetected = true
		}
	}

	return jarPath, autoDetected
}

func buildFilter() *burp.Filter {
	f := burp.NewFilter()
	hasFilter := false

	if hostFilter != "" {
		f.WithHost(hostFilter)
		hasFilter = true
	}

	if pathFilter != "" {
		f.WithPath(pathFilter)
		hasFilter = true
	}

	if methodFilter != "" {
		methods := strings.Split(methodFilter, ",")
		for i := range methods {
			methods[i] = strings.TrimSpace(methods[i])
		}
		f.WithMethod(methods...)
		hasFilter = true
	}

	if statusFilter != "" {
		codes, minCode, maxCode := burp.ParseStatusCodes(statusFilter)
		if len(codes) > 0 {
			f.WithStatusCode(codes...)
		}
		if minCode > 0 || maxCode > 0 {
			f.WithStatusCodeRange(minCode, maxCode)
		}
		hasFilter = true
	}

	if contentTypeFilter != "" {
		f.WithContentType(contentTypeFilter)
		hasFilter = true
	}

	if fromTime != "" {
		if t, err := time.Parse(time.RFC3339, fromTime); err == nil {
			f.WithTimeFrom(t)
			hasFilter = true
		}
	}

	if toTime != "" {
		if t, err := time.Parse(time.RFC3339, toTime); err == nil {
			f.WithTimeTo(t)
			hasFilter = true
		}
	}

	if minSize > 0 {
		f.WithMinSize(minSize)
		hasFilter = true
	}

	if maxSize > 0 {
		f.WithMaxSize(maxSize)
		hasFilter = true
	}

	if !hasFilter {
		return nil
	}

	return f
}

func getOutputWriter() *os.File {
	if outputFile != "" {
		f, err := os.Create(outputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to create output file: %v\n", err)
			return os.Stdout
		}
		return f
	}
	return os.Stdout
}

func closeOutputWriter(f *os.File) {
	if f != os.Stdout && f != os.Stderr {
		f.Close()
	}
}

func formatSize(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
