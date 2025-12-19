package burp

import (
	"context"
	"regexp"
	"strings"
)

type SearchScope int

const (
	SearchAll SearchScope = iota
	SearchRequests
	SearchResponses
	SearchHeaders
	SearchBodies
	SearchURLs
)

type SearchOptions struct {
	Query         string
	CaseSensitive bool
	Scope         SearchScope
	Regex         bool
	MaxResults    int
}

type SearchResult struct {
	Entry    HTTPEntry
	Matches  []SearchMatch
	Score    int
}

type SearchMatch struct {
	Location string
	Context  string
	Offset   int
	Length   int
}

// Search searches through HTTP entries for matching content.
func Search(entries []HTTPEntry, opts SearchOptions) []SearchResult {
	if opts.Query == "" {
		return nil
	}

	var results []SearchResult
	var pattern *regexp.Regexp

	if opts.Regex {
		var err error
		flags := ""
		if !opts.CaseSensitive {
			flags = "(?i)"
		}
		pattern, err = regexp.Compile(flags + opts.Query)
		if err != nil {
			return nil
		}
	}

	searchFunc := func(text, location string) []SearchMatch {
		if opts.Regex {
			return searchRegex(text, pattern, location)
		}
		return searchText(text, opts.Query, opts.CaseSensitive, location)
	}

	for _, entry := range entries {
		var matches []SearchMatch

		switch opts.Scope {
		case SearchAll:
			matches = append(matches, searchEntry(entry, searchFunc)...)
		case SearchRequests:
			if entry.Request != nil {
				matches = append(matches, searchFunc(string(entry.Request.Raw), "request")...)
			}
		case SearchResponses:
			if entry.Response != nil {
				matches = append(matches, searchFunc(string(entry.Response.Raw), "response")...)
			}
		case SearchHeaders:
			if entry.Request != nil {
				matches = append(matches, searchHeaders(entry.Request.Headers, "request_header", searchFunc)...)
			}
			if entry.Response != nil {
				matches = append(matches, searchHeaders(entry.Response.Headers, "response_header", searchFunc)...)
			}
		case SearchBodies:
			if entry.Request != nil && entry.Request.Body != nil {
				matches = append(matches, searchFunc(string(entry.Request.Body), "request_body")...)
			}
			if entry.Response != nil && entry.Response.Body != nil {
				matches = append(matches, searchFunc(string(entry.Response.Body), "response_body")...)
			}
		case SearchURLs:
			matches = append(matches, searchFunc(entry.URL, "url")...)
			matches = append(matches, searchFunc(entry.Path, "path")...)
			if entry.QueryString != "" {
				matches = append(matches, searchFunc(entry.QueryString, "query")...)
			}
		}

		if len(matches) > 0 {
			results = append(results, SearchResult{
				Entry:   entry,
				Matches: matches,
				Score:   len(matches),
			})

			if opts.MaxResults > 0 && len(results) >= opts.MaxResults {
				break
			}
		}
	}

	return results
}

// SearchStream searches through streamed HTTP entries.
func SearchStream(ctx context.Context, entryChan <-chan HTTPEntry, opts SearchOptions) (<-chan SearchResult, <-chan error) {
	resultChan := make(chan SearchResult, 100)
	errChan := make(chan error, 1)

	go func() {
		defer close(resultChan)
		defer close(errChan)

		var pattern *regexp.Regexp
		if opts.Regex {
			var err error
			flags := ""
			if !opts.CaseSensitive {
				flags = "(?i)"
			}
			pattern, err = regexp.Compile(flags + opts.Query)
			if err != nil {
				errChan <- err
				return
			}
		}

		searchFunc := func(text, location string) []SearchMatch {
			if opts.Regex {
				return searchRegex(text, pattern, location)
			}
			return searchText(text, opts.Query, opts.CaseSensitive, location)
		}

		count := 0
		for entry := range entryChan {
			select {
			case <-ctx.Done():
				errChan <- ctx.Err()
				return
			default:
			}

			matches := searchEntry(entry, searchFunc)
			if len(matches) > 0 {
				result := SearchResult{
					Entry:   entry,
					Matches: matches,
					Score:   len(matches),
				}

				select {
				case resultChan <- result:
					count++
					if opts.MaxResults > 0 && count >= opts.MaxResults {
						return
					}
				case <-ctx.Done():
					errChan <- ctx.Err()
					return
				}
			}
		}
	}()

	return resultChan, errChan
}

func searchEntry(entry HTTPEntry, searchFunc func(string, string) []SearchMatch) []SearchMatch {
	var matches []SearchMatch

	matches = append(matches, searchFunc(entry.URL, "url")...)

	if entry.Request != nil {
		matches = append(matches, searchFunc(string(entry.Request.Raw), "request")...)
	}

	if entry.Response != nil {
		matches = append(matches, searchFunc(string(entry.Response.Raw), "response")...)
	}

	return matches
}

func searchText(text, query string, caseSensitive bool, location string) []SearchMatch {
	var matches []SearchMatch

	searchText := text
	searchQuery := query
	if !caseSensitive {
		searchText = strings.ToLower(text)
		searchQuery = strings.ToLower(query)
	}

	offset := 0
	for {
		idx := strings.Index(searchText[offset:], searchQuery)
		if idx == -1 {
			break
		}

		actualIdx := offset + idx
		contextStart := actualIdx - 50
		if contextStart < 0 {
			contextStart = 0
		}
		contextEnd := actualIdx + len(query) + 50
		if contextEnd > len(text) {
			contextEnd = len(text)
		}

		context := text[contextStart:contextEnd]
		context = strings.ReplaceAll(context, "\r\n", " ")
		context = strings.ReplaceAll(context, "\n", " ")

		matches = append(matches, SearchMatch{
			Location: location,
			Context:  context,
			Offset:   actualIdx,
			Length:   len(query),
		})

		offset = actualIdx + len(query)
	}

	return matches
}

func searchRegex(text string, pattern *regexp.Regexp, location string) []SearchMatch {
	var matches []SearchMatch

	locs := pattern.FindAllStringIndex(text, -1)
	for _, loc := range locs {
		contextStart := loc[0] - 50
		if contextStart < 0 {
			contextStart = 0
		}
		contextEnd := loc[1] + 50
		if contextEnd > len(text) {
			contextEnd = len(text)
		}

		context := text[contextStart:contextEnd]
		context = strings.ReplaceAll(context, "\r\n", " ")
		context = strings.ReplaceAll(context, "\n", " ")

		matches = append(matches, SearchMatch{
			Location: location,
			Context:  context,
			Offset:   loc[0],
			Length:   loc[1] - loc[0],
		})
	}

	return matches
}

func searchHeaders(headers map[string][]string, location string, searchFunc func(string, string) []SearchMatch) []SearchMatch {
	var matches []SearchMatch

	for key, values := range headers {
		matches = append(matches, searchFunc(key, location)...)
		for _, v := range values {
			matches = append(matches, searchFunc(v, location)...)
		}
	}

	return matches
}

// QuickSearch performs a simple string search across all entries.
func QuickSearch(entries []HTTPEntry, query string) []HTTPEntry {
	results := Search(entries, SearchOptions{
		Query:         query,
		CaseSensitive: false,
		Scope:         SearchAll,
	})

	var found []HTTPEntry
	for _, r := range results {
		found = append(found, r.Entry)
	}
	return found
}

// SearchByHost finds all entries for a specific host.
func SearchByHost(entries []HTTPEntry, host string) []HTTPEntry {
	var found []HTTPEntry
	for _, entry := range entries {
		if strings.EqualFold(entry.Host, host) {
			found = append(found, entry)
		}
	}
	return found
}

// SearchByPath finds all entries matching a path pattern.
func SearchByPath(entries []HTTPEntry, pathPattern string) []HTTPEntry {
	pattern, err := regexp.Compile(pathPattern)
	if err != nil {
		return nil
	}

	var found []HTTPEntry
	for _, entry := range entries {
		if pattern.MatchString(entry.Path) {
			found = append(found, entry)
		}
	}
	return found
}
