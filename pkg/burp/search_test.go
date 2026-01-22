package burp

import (
	"context"
	"net/http"
	"testing"
	"time"
)

func sampleSearchEntry() HTTPEntry {
	entry := sampleHTTPEntry()
	entry.Request.Headers = http.Header{"X-Test": {"Alpha"}}
	entry.Request.Body = []byte("request-body")
	entry.Response.Headers = http.Header{"X-Resp": {"Beta"}}
	entry.Response.Body = []byte("response-body")
	entry.URL = "https://example.com/path?query=needle"
	entry.Path = "/path"
	entry.QueryString = "query=needle"
	return entry
}

func TestSearchScopes(t *testing.T) {
	entry := sampleSearchEntry()
	entries := []HTTPEntry{entry}

	results := Search(entries, SearchOptions{Query: "needle", Scope: SearchAll})
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	results = Search(entries, SearchOptions{Query: "Alpha", Scope: SearchHeaders})
	if len(results) != 1 {
		t.Fatalf("expected 1 header match, got %d", len(results))
	}

	results = Search(entries, SearchOptions{Query: "request-body", Scope: SearchBodies})
	if len(results) != 1 {
		t.Fatalf("expected 1 body match, got %d", len(results))
	}

	results = Search(entries, SearchOptions{Query: "example.com", Scope: SearchURLs})
	if len(results) != 1 {
		t.Fatalf("expected 1 url match, got %d", len(results))
	}
}

func TestSearchRegexAndCase(t *testing.T) {
	entry := sampleSearchEntry()
	entries := []HTTPEntry{entry}

	results := Search(entries, SearchOptions{Query: "alpha", Scope: SearchHeaders, Regex: false, CaseSensitive: false})
	if len(results) != 1 {
		t.Fatalf("expected case-insensitive match")
	}

	results = Search(entries, SearchOptions{Query: "Alpha", Scope: SearchHeaders, Regex: true, CaseSensitive: true})
	if len(results) != 1 {
		t.Fatalf("expected regex match")
	}

	results = Search(entries, SearchOptions{Query: "[", Scope: SearchAll, Regex: true})
	if results != nil {
		t.Fatal("expected invalid regex to return nil")
	}
}

func TestSearchMaxResults(t *testing.T) {
	entry := sampleSearchEntry()
	entries := []HTTPEntry{entry, entry}
	results := Search(entries, SearchOptions{Query: "needle", Scope: SearchAll, MaxResults: 1})
	if len(results) != 1 {
		t.Fatalf("expected 1 result due to MaxResults, got %d", len(results))
	}
}

func TestSearchStream(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	entries := make(chan HTTPEntry, 2)
	entries <- sampleSearchEntry()
	entries <- sampleSearchEntry()
	close(entries)

	resultsChan, errChan := SearchStream(ctx, entries, SearchOptions{Query: "needle", Scope: SearchAll, MaxResults: 1})

	count := 0
	for range resultsChan {
		count++
	}
	if count != 1 {
		t.Fatalf("expected 1 streamed result, got %d", count)
	}

	select {
	case err := <-errChan:
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	default:
	}
}

func TestSearchStreamEmptyQuery(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	entryChan := make(chan HTTPEntry)
	close(entryChan)

	resultsChan, errChan := SearchStream(ctx, entryChan, SearchOptions{Query: "", Scope: SearchAll})

	select {
	case _, ok := <-resultsChan:
		if ok {
			t.Fatal("expected results channel to be closed")
		}
	default:
		t.Fatal("expected results channel to be closed")
	}

	if err := <-errChan; err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestQuickSearchAndByHostPath(t *testing.T) {
	entry := sampleSearchEntry()
	entries := []HTTPEntry{entry}

	if got := QuickSearch(entries, "needle"); len(got) != 1 {
		t.Fatalf("expected quick search to find 1 entry, got %d", len(got))
	}
	if got := SearchByHost(entries, "EXAMPLE.COM"); len(got) != 1 {
		t.Fatalf("expected search by host to find 1 entry, got %d", len(got))
	}
	if got := SearchByPath(entries, "^/pa"); len(got) != 1 {
		t.Fatalf("expected search by path to find 1 entry, got %d", len(got))
	}
	if got := SearchByPath(entries, "("); got != nil {
		t.Fatalf("expected invalid regex to return nil")
	}
}
