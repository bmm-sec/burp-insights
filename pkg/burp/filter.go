package burp

import (
	"regexp"
	"strings"
	"time"
)

type Filter struct {
	hostPattern     *regexp.Regexp
	pathPattern     *regexp.Regexp
	urlPattern      *regexp.Regexp
	statusCodes     []int
	statusCodeMin   int
	statusCodeMax   int
	contentTypes    []string
	methods         []string
	minSize         int64
	maxSize         int64
	timeFrom        time.Time
	timeTo          time.Time
	hasResponse     *bool
	tools           []ToolType
	contentContains string
	headerContains  string
	bodyContains    string
}

// NewFilter creates a new filter with default settings.
func NewFilter() *Filter {
	return &Filter{}
}

// WithHost filters by host pattern (regex).
func (f *Filter) WithHost(pattern string) *Filter {
	if pattern != "" {
		f.hostPattern, _ = regexp.Compile(pattern)
	}
	return f
}

// WithPath filters by path pattern (regex).
func (f *Filter) WithPath(pattern string) *Filter {
	if pattern != "" {
		f.pathPattern, _ = regexp.Compile(pattern)
	}
	return f
}

// WithURL filters by full URL pattern (regex).
func (f *Filter) WithURL(pattern string) *Filter {
	if pattern != "" {
		f.urlPattern, _ = regexp.Compile(pattern)
	}
	return f
}

// WithStatusCode filters by specific status codes.
func (f *Filter) WithStatusCode(codes ...int) *Filter {
	f.statusCodes = codes
	return f
}

// WithStatusCodeRange filters by status code range (inclusive).
func (f *Filter) WithStatusCodeRange(min, max int) *Filter {
	f.statusCodeMin = min
	f.statusCodeMax = max
	return f
}

// WithContentType filters by content type (substring match).
func (f *Filter) WithContentType(types ...string) *Filter {
	f.contentTypes = types
	return f
}

// WithMethod filters by HTTP method.
func (f *Filter) WithMethod(methods ...string) *Filter {
	for i, m := range methods {
		methods[i] = strings.ToUpper(m)
	}
	f.methods = methods
	return f
}

// WithSizeRange filters by response size range.
func (f *Filter) WithSizeRange(min, max int64) *Filter {
	f.minSize = min
	f.maxSize = max
	return f
}

// WithMinSize filters entries with response size >= min.
func (f *Filter) WithMinSize(min int64) *Filter {
	f.minSize = min
	return f
}

// WithMaxSize filters entries with response size <= max.
func (f *Filter) WithMaxSize(max int64) *Filter {
	f.maxSize = max
	return f
}

// WithTimeRange filters by timestamp range.
func (f *Filter) WithTimeRange(from, to time.Time) *Filter {
	f.timeFrom = from
	f.timeTo = to
	return f
}

// WithTimeFrom filters entries after the given time.
func (f *Filter) WithTimeFrom(from time.Time) *Filter {
	f.timeFrom = from
	return f
}

// WithTimeTo filters entries before the given time.
func (f *Filter) WithTimeTo(to time.Time) *Filter {
	f.timeTo = to
	return f
}

// WithResponse filters entries that have/don't have a response.
func (f *Filter) WithResponse(hasResponse bool) *Filter {
	f.hasResponse = &hasResponse
	return f
}

// WithTool filters by tool source.
func (f *Filter) WithTool(tools ...ToolType) *Filter {
	f.tools = tools
	return f
}

// WithContentContains filters entries containing the string in request or response.
func (f *Filter) WithContentContains(s string) *Filter {
	f.contentContains = s
	return f
}

// WithHeaderContains filters entries containing the string in headers.
func (f *Filter) WithHeaderContains(s string) *Filter {
	f.headerContains = s
	return f
}

// WithBodyContains filters entries containing the string in body.
func (f *Filter) WithBodyContains(s string) *Filter {
	f.bodyContains = s
	return f
}

// Match checks if an entry matches the filter criteria.
func (f *Filter) Match(entry HTTPEntry) bool {
	if f.hostPattern != nil && !f.hostPattern.MatchString(entry.Host) {
		return false
	}

	if f.pathPattern != nil && !f.pathPattern.MatchString(entry.Path) {
		return false
	}

	if f.urlPattern != nil && !f.urlPattern.MatchString(entry.URL) {
		return false
	}

	if len(f.statusCodes) > 0 {
		found := false
		for _, code := range f.statusCodes {
			if entry.StatusCode == code {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	if f.statusCodeMin > 0 || f.statusCodeMax > 0 {
		if f.statusCodeMin > 0 && entry.StatusCode < f.statusCodeMin {
			return false
		}
		if f.statusCodeMax > 0 && entry.StatusCode > f.statusCodeMax {
			return false
		}
	}

	if len(f.contentTypes) > 0 {
		found := false
		for _, ct := range f.contentTypes {
			if strings.Contains(strings.ToLower(entry.MIMEType), strings.ToLower(ct)) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	if len(f.methods) > 0 {
		found := false
		for _, m := range f.methods {
			if strings.EqualFold(entry.Method, m) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	if f.minSize > 0 && entry.ContentLength < f.minSize {
		return false
	}

	if f.maxSize > 0 && entry.ContentLength > f.maxSize {
		return false
	}

	if !f.timeFrom.IsZero() && entry.Timestamp.Before(f.timeFrom) {
		return false
	}

	if !f.timeTo.IsZero() && entry.Timestamp.After(f.timeTo) {
		return false
	}

	if f.hasResponse != nil {
		hasResp := entry.Response != nil
		if *f.hasResponse != hasResp {
			return false
		}
	}

	if len(f.tools) > 0 {
		found := false
		for _, t := range f.tools {
			if entry.ToolSource == t {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	if f.contentContains != "" {
		found := false
		if entry.Request != nil {
			if strings.Contains(string(entry.Request.Raw), f.contentContains) {
				found = true
			}
		}
		if !found && entry.Response != nil {
			if strings.Contains(string(entry.Response.Raw), f.contentContains) {
				found = true
			}
		}
		if !found {
			return false
		}
	}

	if f.headerContains != "" {
		found := false
		if entry.Request != nil {
			for key, values := range entry.Request.Headers {
				if strings.Contains(key, f.headerContains) {
					found = true
					break
				}
				for _, v := range values {
					if strings.Contains(v, f.headerContains) {
						found = true
						break
					}
				}
			}
		}
		if !found && entry.Response != nil {
			for key, values := range entry.Response.Headers {
				if strings.Contains(key, f.headerContains) {
					found = true
					break
				}
				for _, v := range values {
					if strings.Contains(v, f.headerContains) {
						found = true
						break
					}
				}
			}
		}
		if !found {
			return false
		}
	}

	if f.bodyContains != "" {
		found := false
		if entry.Request != nil && entry.Request.Body != nil {
			if strings.Contains(string(entry.Request.Body), f.bodyContains) {
				found = true
			}
		}
		if !found && entry.Response != nil && entry.Response.Body != nil {
			if strings.Contains(string(entry.Response.Body), f.bodyContains) {
				found = true
			}
		}
		if !found {
			return false
		}
	}

	return true
}

// FilterHTTPHistory filters a slice of HTTP entries.
func FilterHTTPHistory(entries []HTTPEntry, f *Filter) []HTTPEntry {
	if f == nil {
		return entries
	}

	var result []HTTPEntry
	for _, entry := range entries {
		if f.Match(entry) {
			result = append(result, entry)
		}
	}
	return result
}

// ParseStatusCodes parses a status code string like "200,301-399,500".
func ParseStatusCodes(s string) (codes []int, minCode int, maxCode int) {
	parts := strings.Split(s, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			rangeParts := strings.Split(part, "-")
			if len(rangeParts) == 2 {
				var min, max int
				parseIntFromString(strings.TrimSpace(rangeParts[0]), &min)
				parseIntFromString(strings.TrimSpace(rangeParts[1]), &max)
				if min > 0 && max > 0 {
					minCode = min
					maxCode = max
				}
			}
		} else {
			var code int
			parseIntFromString(part, &code)
			if code > 0 {
				codes = append(codes, code)
			}
		}
	}
	return
}
