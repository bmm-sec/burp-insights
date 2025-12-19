package burp

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"strings"
	"time"
)

type ExportFormat int

const (
	FormatJSON ExportFormat = iota
	FormatJSONLines
	FormatCSV
	FormatHAR
)

type ExportOptions struct {
	Format      ExportFormat
	IncludeBody bool
	PrettyPrint bool
	MaxBodySize int64
	IncludeRaw  bool
}

func DefaultExportOptions() ExportOptions {
	return ExportOptions{
		Format:      FormatJSON,
		IncludeBody: true,
		PrettyPrint: true,
		MaxBodySize: 10 * 1024,
		IncludeRaw:  false,
	}
}

type ExportedEntry struct {
	ID            uint64           `json:"id"`
	Timestamp     string           `json:"timestamp,omitempty"`
	Host          string           `json:"host"`
	Port          int              `json:"port,omitempty"`
	Protocol      string           `json:"protocol,omitempty"`
	Method        string           `json:"method"`
	Path          string           `json:"path"`
	URL           string           `json:"url"`
	QueryString   string           `json:"query_string,omitempty"`
	StatusCode    int              `json:"status_code,omitempty"`
	ContentLength int64            `json:"content_length,omitempty"`
	MIMEType      string           `json:"mime_type,omitempty"`
	Request       *ExportedMessage `json:"request,omitempty"`
	Response      *ExportedMessage `json:"response,omitempty"`
}

type ExportedMessage struct {
	StartLine string            `json:"start_line,omitempty"`
	Headers   map[string]string `json:"headers,omitempty"`
	Body      string            `json:"body,omitempty"`
	BodySize  int               `json:"body_size,omitempty"`
	Raw       string            `json:"raw,omitempty"`
}

// Export writes HTTP entries to the given writer in the specified format.
func Export(w io.Writer, entries []HTTPEntry, opts ExportOptions) error {
	switch opts.Format {
	case FormatJSON:
		return exportJSON(w, entries, opts)
	case FormatJSONLines:
		return exportJSONLines(w, entries, opts)
	case FormatCSV:
		return exportCSV(w, entries, opts)
	case FormatHAR:
		return exportHAR(w, entries, opts)
	default:
		return exportJSON(w, entries, opts)
	}
}

// ExportProject writes the complete project to the given writer.
func ExportProject(w io.Writer, project *Project, opts ExportOptions) error {
	return Export(w, project.HTTPHistory, opts)
}

func exportJSON(w io.Writer, entries []HTTPEntry, opts ExportOptions) error {
	exported := make([]ExportedEntry, 0, len(entries))
	for _, entry := range entries {
		exported = append(exported, convertToExported(entry, opts))
	}

	encoder := json.NewEncoder(w)
	if opts.PrettyPrint {
		encoder.SetIndent("", "  ")
	}
	return encoder.Encode(exported)
}

func exportJSONLines(w io.Writer, entries []HTTPEntry, opts ExportOptions) error {
	encoder := json.NewEncoder(w)
	for _, entry := range entries {
		exported := convertToExported(entry, opts)
		if err := encoder.Encode(exported); err != nil {
			return err
		}
	}
	return nil
}

func exportCSV(w io.Writer, entries []HTTPEntry, opts ExportOptions) error {
	header := "id,timestamp,method,host,path,url,status_code,content_length,mime_type\n"
	if _, err := w.Write([]byte(header)); err != nil {
		return err
	}

	for _, entry := range entries {
		line := csvEscape(intToString(int(entry.ID))) + "," +
			csvEscape(entry.Timestamp.Format(time.RFC3339)) + "," +
			csvEscape(entry.Method) + "," +
			csvEscape(entry.Host) + "," +
			csvEscape(entry.Path) + "," +
			csvEscape(entry.URL) + "," +
			intToString(entry.StatusCode) + "," +
			intToString(int(entry.ContentLength)) + "," +
			csvEscape(entry.MIMEType) + "\n"

		if _, err := w.Write([]byte(line)); err != nil {
			return err
		}
	}
	return nil
}

func csvEscape(s string) string {
	if strings.ContainsAny(s, ",\"\n\r") {
		s = strings.ReplaceAll(s, "\"", "\"\"")
		return "\"" + s + "\""
	}
	return s
}

type HARLog struct {
	Log HARLogContent `json:"log"`
}

type HARLogContent struct {
	Version string     `json:"version"`
	Creator HARCreator `json:"creator"`
	Entries []HAREntry `json:"entries"`
}

type HARCreator struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type HAREntry struct {
	StartedDateTime string      `json:"startedDateTime"`
	Time            float64     `json:"time"`
	Request         HARRequest  `json:"request"`
	Response        HARResponse `json:"response"`
	Cache           struct{}    `json:"cache"`
	Timings         HARTimings  `json:"timings"`
}

type HARRequest struct {
	Method      string       `json:"method"`
	URL         string       `json:"url"`
	HTTPVersion string       `json:"httpVersion"`
	Headers     []HARHeader  `json:"headers"`
	QueryString []HARParam   `json:"queryString"`
	Cookies     []HARCookie  `json:"cookies"`
	HeadersSize int          `json:"headersSize"`
	BodySize    int          `json:"bodySize"`
	PostData    *HARPostData `json:"postData,omitempty"`
}

type HARResponse struct {
	Status      int         `json:"status"`
	StatusText  string      `json:"statusText"`
	HTTPVersion string      `json:"httpVersion"`
	Headers     []HARHeader `json:"headers"`
	Cookies     []HARCookie `json:"cookies"`
	Content     HARContent  `json:"content"`
	RedirectURL string      `json:"redirectURL"`
	HeadersSize int         `json:"headersSize"`
	BodySize    int         `json:"bodySize"`
}

type HARHeader struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type HARParam struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type HARCookie struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type HARPostData struct {
	MimeType string     `json:"mimeType"`
	Text     string     `json:"text,omitempty"`
	Params   []HARParam `json:"params,omitempty"`
}

type HARContent struct {
	Size     int    `json:"size"`
	MimeType string `json:"mimeType"`
	Text     string `json:"text,omitempty"`
	Encoding string `json:"encoding,omitempty"`
}

type HARTimings struct {
	Send    float64 `json:"send"`
	Wait    float64 `json:"wait"`
	Receive float64 `json:"receive"`
}

func exportHAR(w io.Writer, entries []HTTPEntry, opts ExportOptions) error {
	har := HARLog{
		Log: HARLogContent{
			Version: "1.2",
			Creator: HARCreator{
				Name:    "burp-insights",
				Version: "1.0.0",
			},
			Entries: make([]HAREntry, 0, len(entries)),
		},
	}

	for _, entry := range entries {
		harEntry := convertToHAREntry(entry, opts)
		har.Log.Entries = append(har.Log.Entries, harEntry)
	}

	encoder := json.NewEncoder(w)
	if opts.PrettyPrint {
		encoder.SetIndent("", "  ")
	}
	return encoder.Encode(har)
}

func convertToHAREntry(entry HTTPEntry, opts ExportOptions) HAREntry {
	harEntry := HAREntry{
		StartedDateTime: entry.Timestamp.Format(time.RFC3339),
		Time:            0,
		Request:         convertToHARRequest(entry, opts),
		Response:        convertToHARResponse(entry, opts),
		Timings: HARTimings{
			Send:    -1,
			Wait:    -1,
			Receive: -1,
		},
	}
	return harEntry
}

func convertToHARRequest(entry HTTPEntry, opts ExportOptions) HARRequest {
	req := HARRequest{
		Method:      entry.Method,
		URL:         entry.URL,
		HTTPVersion: entry.Protocol,
		Headers:     make([]HARHeader, 0),
		QueryString: make([]HARParam, 0),
		Cookies:     make([]HARCookie, 0),
		HeadersSize: -1,
		BodySize:    -1,
	}

	if entry.Request != nil {
		for name, values := range entry.Request.Headers {
			for _, value := range values {
				req.Headers = append(req.Headers, HARHeader{Name: name, Value: value})
			}
		}

		if opts.IncludeBody && entry.Request.Body != nil {
			bodySize := len(entry.Request.Body)
			if opts.MaxBodySize > 0 && int64(bodySize) > opts.MaxBodySize {
				bodySize = int(opts.MaxBodySize)
			}
			req.BodySize = bodySize
			req.PostData = &HARPostData{
				MimeType: "application/octet-stream",
				Text:     string(entry.Request.Body[:bodySize]),
			}
		}
	}

	if entry.QueryString != "" {
		params := parseQueryString(entry.QueryString)
		for name, value := range params {
			req.QueryString = append(req.QueryString, HARParam{Name: name, Value: value})
		}
	}

	return req
}

func convertToHARResponse(entry HTTPEntry, opts ExportOptions) HARResponse {
	resp := HARResponse{
		Status:      entry.StatusCode,
		StatusText:  getStatusText(entry.StatusCode),
		HTTPVersion: "HTTP/1.1",
		Headers:     make([]HARHeader, 0),
		Cookies:     make([]HARCookie, 0),
		Content: HARContent{
			Size:     int(entry.ContentLength),
			MimeType: entry.MIMEType,
		},
		RedirectURL: "",
		HeadersSize: -1,
		BodySize:    int(entry.ContentLength),
	}

	if entry.Response != nil {
		for name, values := range entry.Response.Headers {
			for _, value := range values {
				resp.Headers = append(resp.Headers, HARHeader{Name: name, Value: value})
			}
		}

		if opts.IncludeBody && entry.Response.Body != nil {
			bodySize := len(entry.Response.Body)
			if opts.MaxBodySize > 0 && int64(bodySize) > opts.MaxBodySize {
				bodySize = int(opts.MaxBodySize)
			}

			if isBinaryContent(entry.MIMEType) {
				resp.Content.Text = base64.StdEncoding.EncodeToString(entry.Response.Body[:bodySize])
				resp.Content.Encoding = "base64"
			} else {
				resp.Content.Text = string(entry.Response.Body[:bodySize])
			}
		}
	}

	return resp
}

func convertToExported(entry HTTPEntry, opts ExportOptions) ExportedEntry {
	exported := ExportedEntry{
		ID:            entry.ID,
		Host:          entry.Host,
		Port:          entry.Port,
		Protocol:      entry.Protocol,
		Method:        entry.Method,
		Path:          entry.Path,
		URL:           entry.URL,
		QueryString:   entry.QueryString,
		StatusCode:    entry.StatusCode,
		ContentLength: entry.ContentLength,
		MIMEType:      entry.MIMEType,
	}

	if !entry.Timestamp.IsZero() {
		exported.Timestamp = entry.Timestamp.Format(time.RFC3339)
	}

	if entry.Request != nil {
		exported.Request = convertMessage(entry.Request, opts)
	}

	if entry.Response != nil {
		exported.Response = convertMessage(entry.Response, opts)
	}

	return exported
}

func convertMessage(msg *HTTPMessage, opts ExportOptions) *ExportedMessage {
	exported := &ExportedMessage{
		StartLine: msg.StartLine,
		Headers:   make(map[string]string),
	}

	for name, values := range msg.Headers {
		if len(values) > 0 {
			exported.Headers[name] = values[0]
		}
	}

	if opts.IncludeBody && msg.Body != nil {
		bodySize := len(msg.Body)
		exported.BodySize = bodySize

		if opts.MaxBodySize > 0 && int64(bodySize) > opts.MaxBodySize {
			bodySize = int(opts.MaxBodySize)
		}
		exported.Body = string(msg.Body[:bodySize])
	}

	if opts.IncludeRaw && msg.Raw != nil {
		rawSize := len(msg.Raw)
		if opts.MaxBodySize > 0 && int64(rawSize) > opts.MaxBodySize*2 {
			rawSize = int(opts.MaxBodySize * 2)
		}
		exported.Raw = string(msg.Raw[:rawSize])
	}

	return exported
}

func parseQueryString(qs string) map[string]string {
	params := make(map[string]string)
	pairs := strings.Split(qs, "&")
	for _, pair := range pairs {
		parts := strings.SplitN(pair, "=", 2)
		if len(parts) == 2 {
			params[parts[0]] = parts[1]
		} else if len(parts) == 1 {
			params[parts[0]] = ""
		}
	}
	return params
}

func getStatusText(code int) string {
	statusTexts := map[int]string{
		200: "OK",
		201: "Created",
		204: "No Content",
		301: "Moved Permanently",
		302: "Found",
		304: "Not Modified",
		400: "Bad Request",
		401: "Unauthorized",
		403: "Forbidden",
		404: "Not Found",
		405: "Method Not Allowed",
		500: "Internal Server Error",
		502: "Bad Gateway",
		503: "Service Unavailable",
	}

	if text, ok := statusTexts[code]; ok {
		return text
	}
	return "Unknown"
}

func isBinaryContent(mimeType string) bool {
	mimeType = strings.ToLower(mimeType)
	textTypes := []string{
		"text/",
		"application/json",
		"application/xml",
		"application/javascript",
		"application/x-www-form-urlencoded",
	}

	for _, t := range textTypes {
		if strings.HasPrefix(mimeType, t) {
			return false
		}
	}
	return true
}
