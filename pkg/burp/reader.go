package burp

import (
	"context"
	"sync"
)

type Reader struct {
	parser   *Parser
	path     string
	cache    *projectCache
	mu       sync.RWMutex
	metadata *ProjectMetadata
}

type projectCache struct {
	httpHistory []HTTPEntry
	locations   []HTTPRecordLocation
	loaded      bool
}

type ReaderOptions struct {
	PreloadHistory bool
	BufferSize     int
	MaxRecordSize  int64
}

func DefaultReaderOptions() ReaderOptions {
	return ReaderOptions{
		PreloadHistory: false,
		BufferSize:     256 * 1024,
		MaxRecordSize:  10 * 1024 * 1024,
	}
}

// Open opens a Burp project file for reading.
func Open(path string) (*Reader, error) {
	return OpenWithOptions(path, DefaultReaderOptions())
}

// OpenWithOptions opens a Burp project file with custom options.
func OpenWithOptions(path string, opts ReaderOptions) (*Reader, error) {
	parser, err := NewParser(path)
	if err != nil {
		return nil, err
	}

	r := &Reader{
		parser: parser,
		path:   path,
		cache:  &projectCache{},
	}

	meta, err := parser.GetMetadata()
	if err != nil {
		parser.Close()
		return nil, err
	}
	r.metadata = meta

	if opts.PreloadHistory {
		_, err := r.HTTPHistory()
		if err != nil {
			parser.Close()
			return nil, err
		}
	}

	return r, nil
}

// Close closes the reader and releases resources.
func (r *Reader) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.parser != nil {
		return r.parser.Close()
	}
	return nil
}

// Path returns the file path of the Burp project.
func (r *Reader) Path() string {
	return r.path
}

// Metadata returns project metadata.
func (r *Reader) Metadata() *ProjectMetadata {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.metadata
}

// HTTPHistory returns all HTTP entries from the project.
func (r *Reader) HTTPHistory() ([]HTTPEntry, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.cache.loaded {
		return r.cache.httpHistory, nil
	}

	locations, err := r.parser.ScanHTTPRecords()
	if err != nil {
		return nil, err
	}

	r.cache.locations = locations

	var entries []HTTPEntry
	for _, loc := range locations {
		entry, err := r.parser.ParseHTTPEntry(loc)
		if err != nil {
			continue
		}
		entries = append(entries, *entry)
	}

	r.cache.httpHistory = entries
	r.cache.loaded = true
	r.metadata.RecordCount = len(entries)

	return entries, nil
}

// HTTPHistoryCount returns the number of HTTP entries without loading all data.
func (r *Reader) HTTPHistoryCount() (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.cache.loaded {
		return len(r.cache.httpHistory), nil
	}

	if len(r.cache.locations) > 0 {
		return len(r.cache.locations), nil
	}

	locations, err := r.parser.ScanHTTPRecords()
	if err != nil {
		return 0, err
	}

	r.cache.locations = locations
	return len(locations), nil
}

// StreamHTTPHistory returns channels for streaming HTTP entries.
func (r *Reader) StreamHTTPHistory(ctx context.Context) (<-chan HTTPEntry, <-chan error) {
	entryChan := make(chan HTTPEntry, 100)
	errChan := make(chan error, 1)

	go func() {
		defer close(entryChan)
		defer close(errChan)

		r.mu.Lock()
		if len(r.cache.locations) == 0 {
			locations, err := r.parser.ScanHTTPRecords()
			if err != nil {
				r.mu.Unlock()
				errChan <- err
				return
			}
			r.cache.locations = locations
		}
		locations := r.cache.locations
		r.mu.Unlock()

		for _, loc := range locations {
			select {
			case <-ctx.Done():
				errChan <- ctx.Err()
				return
			default:
				entry, err := r.parser.ParseHTTPEntry(loc)
				if err != nil {
					continue
				}

				select {
				case entryChan <- *entry:
				case <-ctx.Done():
					errChan <- ctx.Err()
					return
				}
			}
		}
	}()

	return entryChan, errChan
}

// Project loads and returns the complete project data.
func (r *Reader) Project() (*Project, error) {
	history, err := r.HTTPHistory()
	if err != nil {
		return nil, err
	}

	project := &Project{
		FilePath:    r.path,
		Magic:       MagicBytes,
		HTTPHistory: history,
		Metadata:    *r.metadata,
	}

	project.SiteMap = buildSiteMap(history)

	return project, nil
}

func buildSiteMap(entries []HTTPEntry) *SiteMap {
	siteMap := &SiteMap{
		Root: make(map[string]*SiteMapNode),
	}

	for i := range entries {
		entry := &entries[i]
		if entry.Host == "" {
			continue
		}

		hostNode, ok := siteMap.Root[entry.Host]
		if !ok {
			hostNode = &SiteMapNode{
				Host:     entry.Host,
				Path:     "/",
				Children: make(map[string]*SiteMapNode),
			}
			siteMap.Root[entry.Host] = hostNode
		}

		hostNode.Entries = append(hostNode.Entries, entry)
	}

	return siteMap
}
