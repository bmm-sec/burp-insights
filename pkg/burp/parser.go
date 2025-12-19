package burp

import (
	"bytes"
	stdbinary "encoding/binary"
	"errors"
	"regexp"
	"strings"
	"sync"
	"unicode/utf16"

	"github.com/bmm-sec/burp-insights/internal/binary"
)

const (
	MagicBytes  uint32 = 0x66858280
	HeaderSize  int    = 256
	MaxBodySize int64  = 10 * 1024 * 1024
)

var (
	ErrInvalidFile     = errors.New("invalid burp project file")
	ErrInvalidMagic    = errors.New("invalid magic bytes")
	ErrParseError      = errors.New("parse error")
	httpMethodPatterns = [][]byte{
		[]byte("GET "),
		[]byte("POST "),
		[]byte("PUT "),
		[]byte("DELETE "),
		[]byte("PATCH "),
		[]byte("HEAD "),
		[]byte("OPTIONS "),
	}
	httpResponsePattern = []byte("HTTP/1.")
	hostHeaderPattern   = regexp.MustCompile(`(?i)^Host:\s*(.+)$`)
	contentTypePattern  = regexp.MustCompile(`(?i)^Content-Type:\s*(.+)$`)
)

type Parser struct {
	reader *binary.Reader
	path   string
	mu     sync.RWMutex
}

func NewParser(path string) (*Parser, error) {
	reader, err := binary.NewReader(path)
	if err != nil {
		return nil, err
	}

	p := &Parser{
		reader: reader,
		path:   path,
	}

	if err := p.validateHeader(); err != nil {
		reader.Close()
		return nil, err
	}

	return p, nil
}

func (p *Parser) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.reader.Close()
}

func (p *Parser) validateHeader() error {
	magic, err := p.reader.ReadUint32At(0)
	if err != nil {
		return ErrInvalidFile
	}

	if magic != MagicBytes {
		return ErrInvalidMagic
	}

	return nil
}

func (p *Parser) GetMetadata() (*ProjectMetadata, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	return &ProjectMetadata{
		FileSize: p.reader.Size(),
	}, nil
}

type HTTPRecordLocation struct {
	RequestOffset  int64
	RequestLength  int
	ResponseOffset int64
	ResponseLength int
}

func (p *Parser) ScanHTTPRecords() ([]HTTPRecordLocation, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	fileSize := p.reader.Size()
	bufSize := 1024 * 1024

	var allOffsets []int64
	offset := int64(HeaderSize)

	for offset < fileSize {
		readSize := bufSize
		remaining := fileSize - offset
		if remaining < int64(bufSize) {
			readSize = int(remaining)
		}

		data, err := p.reader.ReadAt(offset, readSize)
		if err != nil || len(data) == 0 {
			break
		}

		for _, pattern := range httpMethodPatterns {
			idx := 0
			for {
				pos := bytes.Index(data[idx:], pattern)
				if pos == -1 {
					break
				}
				actualPos := idx + pos
				if actualPos > 0 && data[actualPos-1] != '\n' && data[actualPos-1] != 0 && actualPos >= 8 {
					allOffsets = append(allOffsets, offset+int64(actualPos))
				} else if actualPos == 0 {
					allOffsets = append(allOffsets, offset+int64(actualPos))
				}
				idx = actualPos + len(pattern)
				if idx >= len(data) {
					break
				}
			}
		}

		overlap := 20
		if len(data) > overlap {
			offset += int64(len(data) - overlap)
		} else {
			offset += int64(len(data))
		}
	}

	allOffsets = deduplicateOffsets(allOffsets)

	var locations []HTTPRecordLocation
	for _, off := range allOffsets {
		loc := p.parseRecordAtOffset(off)
		if loc.RequestLength > 0 {
			locations = append(locations, loc)
		}
	}

	return locations, nil
}

func deduplicateOffsets(offsets []int64) []int64 {
	if len(offsets) == 0 {
		return offsets
	}

	seen := make(map[int64]bool)
	var result []int64
	for _, off := range offsets {
		if !seen[off] {
			seen[off] = true
			result = append(result, off)
		}
	}
	return result
}

func (p *Parser) parseRecordAtOffset(offset int64) HTTPRecordLocation {
	loc := HTTPRecordLocation{RequestOffset: offset}

	maxReadSize := 128 * 1024
	data, err := p.reader.ReadAt(offset, maxReadSize)
	if err != nil || len(data) < 10 {
		return loc
	}

	reqEnd := findHTTPRequestEnd(data)
	if reqEnd <= 0 || reqEnd > len(data) {
		headerEnd := bytes.Index(data, []byte("\r\n\r\n"))
		if headerEnd > 0 {
			reqEnd = headerEnd + 4
		} else {
			reqEnd = 1024
			if reqEnd > len(data) {
				reqEnd = len(data)
			}
		}
	}
	loc.RequestLength = reqEnd

	searchStart := reqEnd
	if searchStart > len(data)-10 {
		return loc
	}

	respIdx := bytes.Index(data[searchStart:], httpResponsePattern)
	if respIdx >= 0 {
		loc.ResponseOffset = offset + int64(searchStart) + int64(respIdx)
		respData := data[searchStart+respIdx:]

		respEnd := findHTTPResponseEnd(respData)
		if respEnd > 0 {
			loc.ResponseLength = respEnd
		}
	}

	return loc
}

func findHTTPRequestEnd(data []byte) int {
	idx := bytes.Index(data, []byte("\r\n\r\n"))
	if idx == -1 {
		idx = bytes.Index(data, []byte("\n\n"))
		if idx != -1 {
			return idx + 2
		}
		return -1
	}

	headerEnd := idx + 4
	headers := string(data[:idx])
	contentLength := extractContentLength(headers)

	if contentLength > 0 && contentLength < 100000 {
		bodyEnd := headerEnd + contentLength
		if bodyEnd <= len(data) {
			return bodyEnd
		}
	}

	return headerEnd
}

func findHTTPResponseEnd(data []byte) int {
	idx := bytes.Index(data, []byte("\r\n\r\n"))
	if idx == -1 {
		idx = bytes.Index(data, []byte("\n\n"))
		if idx != -1 {
			return idx + 2
		}
		return -1
	}

	headerEnd := idx + 4
	headers := string(data[:idx])
	contentLength := extractContentLength(headers)

	if contentLength > 0 && contentLength < 500000 {
		bodyEnd := headerEnd + contentLength
		if bodyEnd <= len(data) {
			return bodyEnd
		}
		return len(data)
	}

	searchData := data[headerEnd:]
	nextHTTP := -1
	for _, pattern := range httpMethodPatterns {
		pos := bytes.Index(searchData, pattern)
		if pos > 0 && (nextHTTP == -1 || pos < nextHTTP) {
			nextHTTP = pos
		}
	}

	httpPos := bytes.Index(searchData, []byte("HTTP/1."))
	if httpPos > 0 && (nextHTTP == -1 || httpPos < nextHTTP) {
		nextHTTP = httpPos
	}

	if nextHTTP > 0 {
		return headerEnd + nextHTTP
	}

	maxBody := 50000
	if len(searchData) < maxBody {
		return len(data)
	}
	return headerEnd + maxBody
}

func extractContentLength(headers string) int {
	lines := strings.Split(headers, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToLower(line), "content-length:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				var length int
				_, _ = parseIntFromString(strings.TrimSpace(parts[1]), &length)
				return length
			}
		}
	}
	return 0
}

func parseIntFromString(s string, result *int) (bool, error) {
	var n int
	for _, c := range s {
		if c >= '0' && c <= '9' {
			n = n*10 + int(c-'0')
		} else {
			break
		}
	}
	*result = n
	return n > 0, nil
}

func (p *Parser) ParseHTTPEntry(loc HTTPRecordLocation) (*HTTPEntry, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	entry := &HTTPEntry{
		ID: uint64(loc.RequestOffset),
	}

	if loc.RequestLength > 0 {
		reqData, err := p.reader.ReadAt(loc.RequestOffset, loc.RequestLength)
		if err != nil {
			return nil, err
		}

		entry.Request = parseHTTPMessage(reqData)
		parseRequestLine(entry, entry.Request.StartLine)
		extractHostFromHeaders(entry, entry.Request.Headers)
	}

	if loc.ResponseLength > 0 && loc.ResponseOffset > 0 {
		respData, err := p.reader.ReadAt(loc.ResponseOffset, loc.ResponseLength)
		if err != nil {
			return entry, nil
		}

		entry.Response = parseHTTPMessage(respData)
		parseStatusLine(entry, entry.Response.StartLine)
		extractContentTypeFromHeaders(entry, entry.Response.Headers)
	}

	buildURL(entry)

	return entry, nil
}

func parseHTTPMessage(data []byte) *HTTPMessage {
	msg := &HTTPMessage{
		Raw:     data,
		Headers: make(map[string][]string),
	}

	headerEnd := bytes.Index(data, []byte("\r\n\r\n"))
	bodyStart := headerEnd + 4
	if headerEnd == -1 {
		headerEnd = bytes.Index(data, []byte("\n\n"))
		bodyStart = headerEnd + 2
	}

	if headerEnd == -1 {
		headerEnd = len(data)
		bodyStart = len(data)
	}

	headerSection := string(data[:headerEnd])
	lines := strings.Split(headerSection, "\n")

	if len(lines) > 0 {
		msg.StartLine = strings.TrimSpace(lines[0])
	}

	for i := 1; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}

		idx := strings.Index(line, ":")
		if idx > 0 {
			key := strings.TrimSpace(line[:idx])
			value := strings.TrimSpace(line[idx+1:])
			msg.Headers[key] = append(msg.Headers[key], value)
		}
	}

	if bodyStart < len(data) {
		msg.Body = data[bodyStart:]
	}

	return msg
}

func parseRequestLine(entry *HTTPEntry, line string) {
	parts := strings.Fields(line)
	if len(parts) >= 2 {
		entry.Method = parts[0]
		fullPath := parts[1]

		if idx := strings.Index(fullPath, "?"); idx >= 0 {
			entry.Path = fullPath[:idx]
			entry.QueryString = fullPath[idx+1:]
		} else {
			entry.Path = fullPath
		}
	}
	if len(parts) >= 3 {
		entry.Protocol = parts[2]
	}
}

func parseStatusLine(entry *HTTPEntry, line string) {
	parts := strings.Fields(line)
	if len(parts) >= 2 {
		var code int
		parseIntFromString(parts[1], &code)
		entry.StatusCode = code
	}
}

func extractHostFromHeaders(entry *HTTPEntry, headers map[string][]string) {
	for key, values := range headers {
		if strings.EqualFold(key, "Host") && len(values) > 0 {
			hostPort := values[0]
			if idx := strings.Index(hostPort, ":"); idx >= 0 {
				entry.Host = hostPort[:idx]
				var port int
				parseIntFromString(hostPort[idx+1:], &port)
				entry.Port = port
			} else {
				entry.Host = hostPort
				entry.Port = 80
			}
			break
		}
	}
}

func extractContentTypeFromHeaders(entry *HTTPEntry, headers map[string][]string) {
	for key, values := range headers {
		if strings.EqualFold(key, "Content-Type") && len(values) > 0 {
			entry.MIMEType = values[0]
			if idx := strings.Index(entry.MIMEType, ";"); idx >= 0 {
				entry.MIMEType = strings.TrimSpace(entry.MIMEType[:idx])
			}
			break
		}
	}

	for key, values := range headers {
		if strings.EqualFold(key, "Content-Length") && len(values) > 0 {
			var length int
			parseIntFromString(values[0], &length)
			entry.ContentLength = int64(length)
			break
		}
	}
}

func buildURL(entry *HTTPEntry) {
	if entry.Host == "" {
		return
	}

	scheme := "http"
	if entry.Port == 443 {
		scheme = "https"
	}

	if entry.Port == 80 || entry.Port == 443 {
		entry.URL = scheme + "://" + entry.Host + entry.Path
	} else {
		entry.URL = scheme + "://" + entry.Host + ":" + intToString(entry.Port) + entry.Path
	}

	if entry.QueryString != "" {
		entry.URL += "?" + entry.QueryString
	}
}

func intToString(n int) string {
	if n == 0 {
		return "0"
	}

	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}

func (p *Parser) ScanRepeaterTabNames() ([]string, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	fileSize := p.reader.Size()
	bufSize := 1024 * 1024

	var tabNames []string
	seenNames := make(map[string]struct{})

	stringRecordHeader := []byte{0x00, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 0x20}
	repeaterRecordMarker := []byte{0x00, 0x02, 0x01, 0x00, 0x0a, 0x02, 0x00, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x58}

	const (
		stringChars       = 32
		stringOffset      = 8
		markerOffset      = 0xb8
		minRequiredLength = markerOffset + 16
	)

	offset := int64(HeaderSize)

	for offset < fileSize {
		readSize := bufSize
		remaining := fileSize - offset
		if remaining < int64(bufSize) {
			readSize = int(remaining)
		}

		data, err := p.reader.ReadAt(offset, readSize)
		if err != nil || len(data) == 0 {
			break
		}

		searchIdx := 0
		for {
			pos := bytes.Index(data[searchIdx:], stringRecordHeader)
			if pos == -1 {
				break
			}
			i := searchIdx + pos

			if i+minRequiredLength <= len(data) && matchesPattern(data[i+markerOffset:], repeaterRecordMarker) {
				name := extractFixedUTF16BEString(data[i+stringOffset:], stringChars)
				if name != "" {
					if _, ok := seenNames[name]; !ok {
						seenNames[name] = struct{}{}
						tabNames = append(tabNames, name)
					}
				}
			}

			searchIdx = i + 1
		}

		overlap := 512
		if len(data) > overlap {
			offset += int64(len(data) - overlap)
		} else {
			offset += int64(len(data))
		}
	}

	return tabNames, nil
}

func matchesPattern(data []byte, pattern []byte) bool {
	if len(data) < len(pattern) {
		return false
	}
	for i := 0; i < len(pattern); i++ {
		if data[i] != pattern[i] {
			return false
		}
	}
	return true
}

func extractFixedUTF16BEString(data []byte, maxChars int) string {
	maxBytes := maxChars * 2
	if len(data) < maxBytes {
		maxBytes = len(data) - (len(data) % 2)
	}

	units := make([]uint16, 0, maxChars)
	for i := 0; i+1 < maxBytes; i += 2 {
		unit := stdbinary.BigEndian.Uint16(data[i : i+2])
		if unit == 0 {
			break
		}
		units = append(units, unit)
	}

	if len(units) == 0 {
		return ""
	}

	return string(utf16.Decode(units))
}
