package burp

import (
	"bytes"
	stdbinary "encoding/binary"
	"errors"
	"fmt"
	"strings"
	"unicode/utf16"
)

var scannerIssueEntrySignature = []byte{
	0x00, 0x00, 0x00, 0x12,
	0x00, 0x00, 0x3a,
	0x01, 0x00, 0x42,
	0x02, 0x00, 0x4a,
	0x03, 0x00, 0x52,
	0x04, 0x00, 0x5a,
	0x05, 0x00, 0x62,
	0x06, 0x00, 0x6a,
	0x07, 0x00, 0x6b,
	0x08, 0x00, 0x6c,
	0x09, 0x00, 0x6d,
	0x0a, 0x00, 0x6e,
	0x0b, 0x00, 0x72,
	0x0c, 0x00, 0x73,
	0x0d, 0x00, 0x7b,
	0x0e, 0x00, 0x83,
	0x0f, 0x00, 0x8b,
	0x10, 0x00, 0x8f,
	0x11, 0x00, 0x97,
}

var scannerIssueIndexEntrySignature = []byte{
	0x00, 0x00, 0x00, 0x07,
	0x00, 0x00, 0x19,
	0x01, 0x00, 0x1d,
	0x02, 0x00, 0x1e,
	0x03, 0x00, 0x26,
	0x04, 0x00, 0x27,
	0x05, 0x00, 0x2f,
	0x06, 0x00, 0x37,
}

type ScannerIssueMeta struct {
	RecordOffset int64                  `json:"recordOffset"`
	SerialNumber uint64                 `json:"serialNumber"`
	TaskID       uint64                 `json:"taskId"`
	Type         uint32                 `json:"type"`
	Severity     Severity               `json:"severity"`
	Confidence   Confidence             `json:"confidence"`
	Host         string                 `json:"host,omitempty"`
	Path         string                 `json:"path,omitempty"`
	Location     string                 `json:"location,omitempty"`
	Definition   *IssueDefinition       `json:"definition,omitempty"`
	Evidence     []ScannerIssueEvidence `json:"evidence,omitempty"`
}

type ScannerIssueEvidence struct {
	Request  *ExportedMessage `json:"request,omitempty"`
	Response *ExportedMessage `json:"response,omitempty"`
}

func (p *Parser) ScanScannerIssueMetas(filterSerialNumbers map[uint64]struct{}) ([]ScannerIssueMeta, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	fileSize := p.reader.Size()
	bufSize := 1024 * 1024

	const (
		issueEntryPtrOffset = 0x2f
		minEntryRecordLen   = issueEntryPtrOffset + 8

		serialOffset      = 0x3a
		taskIDOffset      = 0x42
		p4aOffset         = 0x4a
		p52Offset         = 0x52
		sevOffset         = 0x6a
		confOffset        = 0x6b
		p73Offset         = 0x73
		typeOffset        = 0x8b
		minIssueRecordLen = 0x98
	)

	seenSerials := make(map[uint64]struct{})
	var metas []ScannerIssueMeta

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
			pos := bytes.Index(data[searchIdx:], scannerIssueIndexEntrySignature)
			if pos == -1 {
				break
			}
			i := searchIdx + pos
			abs := offset + int64(i)

			rec, err := p.reader.ReadAt(abs, minEntryRecordLen)
			if err != nil || len(rec) < minEntryRecordLen {
				searchIdx = i + 1
				continue
			}
			if !bytes.HasPrefix(rec, scannerIssueIndexEntrySignature) {
				searchIdx = i + 1
				continue
			}

			issuePtr := int64(stdbinary.BigEndian.Uint64(rec[issueEntryPtrOffset : issueEntryPtrOffset+8]))
			meta, ok := p.readScannerIssueMetaAtOffset(issuePtr, minIssueRecordLen, serialOffset, taskIDOffset, p4aOffset, p52Offset, sevOffset, confOffset, p73Offset, typeOffset, filterSerialNumbers, seenSerials)
			if ok {
				metas = append(metas, meta)
			}

			searchIdx = i + 1
		}

		overlap := 1024
		if len(data) > overlap {
			offset += int64(len(data) - overlap)
		} else {
			offset += int64(len(data))
		}
	}

	return metas, nil
}

func (p *Parser) ScanScannerIssueMetasRaw(filterSerialNumbers map[uint64]struct{}) ([]ScannerIssueMeta, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	fileSize := p.reader.Size()
	bufSize := 1024 * 1024

	const (
		serialOffset      = 0x3a
		taskIDOffset      = 0x42
		p4aOffset         = 0x4a
		p52Offset         = 0x52
		sevOffset         = 0x6a
		confOffset        = 0x6b
		p73Offset         = 0x73
		typeOffset        = 0x8b
		minIssueRecordLen = 0x98
	)

	seenSerials := make(map[uint64]struct{})
	var metas []ScannerIssueMeta

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
			pos := bytes.Index(data[searchIdx:], scannerIssueEntrySignature)
			if pos == -1 {
				break
			}
			i := searchIdx + pos
			abs := offset + int64(i)

			meta, ok := p.readScannerIssueMetaAtOffset(abs, minIssueRecordLen, serialOffset, taskIDOffset, p4aOffset, p52Offset, sevOffset, confOffset, p73Offset, typeOffset, filterSerialNumbers, seenSerials)
			if ok {
				metas = append(metas, meta)
			}

			searchIdx = i + 1
		}

		overlap := 1024
		if len(data) > overlap {
			offset += int64(len(data) - overlap)
		} else {
			offset += int64(len(data))
		}
	}

	return metas, nil
}

func (p *Parser) readScannerIssueMetaAtOffset(abs int64, minIssueRecordLen int, serialOffset int, taskIDOffset int, p4aOffset int, p52Offset int, sevOffset int, confOffset int, p73Offset int, typeOffset int, filterSerialNumbers map[uint64]struct{}, seenSerials map[uint64]struct{}) (ScannerIssueMeta, bool) {
	if abs <= 0 || abs >= p.reader.Size() {
		return ScannerIssueMeta{}, false
	}

	rec, err := p.reader.ReadAt(abs, minIssueRecordLen)
	if err != nil || len(rec) < minIssueRecordLen {
		return ScannerIssueMeta{}, false
	}
	if !bytes.HasPrefix(rec, scannerIssueEntrySignature) {
		return ScannerIssueMeta{}, false
	}

	serial := stdbinary.BigEndian.Uint64(rec[serialOffset : serialOffset+8])
	if filterSerialNumbers != nil {
		if _, ok := filterSerialNumbers[serial]; !ok {
			return ScannerIssueMeta{}, false
		}
	}
	if _, ok := seenSerials[serial]; ok {
		return ScannerIssueMeta{}, false
	}
	seenSerials[serial] = struct{}{}

	sev, ok := severityFromBurpByte(rec[sevOffset])
	if !ok {
		return ScannerIssueMeta{}, false
	}
	conf, ok := confidenceFromBurpByte(rec[confOffset])
	if !ok {
		return ScannerIssueMeta{}, false
	}

	taskID := stdbinary.BigEndian.Uint64(rec[taskIDOffset : taskIDOffset+8])
	typeID := stdbinary.BigEndian.Uint32(rec[typeOffset : typeOffset+4])
	pathPtr := int64(stdbinary.BigEndian.Uint64(rec[p4aOffset : p4aOffset+8]))
	locationPtr := int64(stdbinary.BigEndian.Uint64(rec[p52Offset : p52Offset+8]))
	reqRecPtr := int64(stdbinary.BigEndian.Uint64(rec[p73Offset : p73Offset+8]))

	path, _ := p.readUTF8StringRecord(pathPtr)
	location, _ := p.readUTF16BEStringRecord(locationPtr)

	evidence, host, reqPath := p.extractIssueEvidence(reqRecPtr)
	if host == "" || reqPath == "" {
		fallbackHost, fallbackPath := p.extractHostAndPathFromRequestRecord(reqRecPtr)
		if host == "" {
			host = fallbackHost
		}
		if reqPath == "" {
			reqPath = fallbackPath
		}
	}
	if reqPath != "" {
		path = reqPath
	}

	var def *IssueDefinition
	if d, ok := IssueDefinitionForType(typeID); ok {
		def = &d
	}

	return ScannerIssueMeta{
		RecordOffset: abs,
		SerialNumber: serial,
		TaskID:       taskID,
		Type:         typeID,
		Severity:     sev,
		Confidence:   conf,
		Host:         host,
		Path:         path,
		Location:     location,
		Definition:   def,
		Evidence:     evidence,
	}, true
}

func severityFromBurpByte(b byte) (Severity, bool) {
	switch b {
	case 1:
		return SeverityInfo, true
	case 2:
		return SeverityLow, true
	case 3:
		return SeverityMedium, true
	case 4:
		return SeverityHigh, true
	default:
		return SeverityInfo, false
	}
}

func confidenceFromBurpByte(b byte) (Confidence, bool) {
	switch b {
	case 1:
		return ConfidenceTentative, true
	case 2:
		return ConfidenceFirm, true
	case 3:
		return ConfidenceCertain, true
	default:
		return ConfidenceTentative, false
	}
}

func (p *Parser) readUTF8StringRecord(offset int64) (string, error) {
	if offset <= 0 {
		return "", errors.New("invalid string offset")
	}

	header, err := p.reader.ReadAt(offset, 8)
	if err != nil || len(header) < 8 {
		return "", fmt.Errorf("read string header: %w", err)
	}

	totalLen := stdbinary.BigEndian.Uint32(header[0:4])
	byteLen := stdbinary.BigEndian.Uint32(header[4:8])
	if totalLen != 8+byteLen {
		return "", fmt.Errorf("invalid UTF-8 string record length: total=%d bytes=%d", totalLen, byteLen)
	}

	if byteLen == 0 {
		return "", nil
	}

	data, err := p.reader.ReadAt(offset+8, int(byteLen))
	if err != nil || len(data) < int(byteLen) {
		return "", fmt.Errorf("read string bytes: %w", err)
	}

	return strings.TrimRight(string(data), "\x00"), nil
}

func (p *Parser) readUTF16BEStringRecord(pointerOffset int64) (string, error) {
	if pointerOffset <= 0 {
		return "", errors.New("invalid UTF-16 string pointer")
	}

	candidates := []int64{pointerOffset, pointerOffset + 2, pointerOffset - 2}
	var lastErr error

	for _, start := range candidates {
		s, ok, err := p.tryReadUTF16BEStringRecordV1(start)
		if ok {
			return s, nil
		}
		if err != nil {
			lastErr = err
		}

		s, ok, err = p.tryReadUTF16BEStringRecordV2(start)
		if ok {
			return s, nil
		}
		if err != nil {
			lastErr = err
		}
	}

	if lastErr == nil {
		lastErr = errors.New("unable to parse UTF-16 string record")
	}
	return "", lastErr
}

func (p *Parser) tryReadUTF16BEStringRecordV1(start int64) (string, bool, error) {
	const headerLen = 32

	stringHeaderPrefix := []byte{0x00, 0x02, 0x00, 0x00, 0x0a, 0x01, 0x00, 0x12, 0x00, 0x00, 0x00, 0x00}

	header, err := p.reader.ReadAt(start, headerLen)
	if err != nil || len(header) < headerLen {
		return "", false, fmt.Errorf("read UTF-16 record header: %w", err)
	}
	if !bytes.HasPrefix(header, stringHeaderPrefix) {
		return "", false, errors.New("unexpected UTF-16 record prefix")
	}

	totalLen := stdbinary.BigEndian.Uint64(header[20:28])
	charLen := stdbinary.BigEndian.Uint32(header[28:32])
	if totalLen != 8+uint64(charLen)*2 {
		return "", false, fmt.Errorf("invalid UTF-16 record length: total=%d chars=%d", totalLen, charLen)
	}
	if charLen == 0 {
		return "", true, nil
	}
	if charLen > 1_000_000 {
		return "", false, fmt.Errorf("UTF-16 record too large: chars=%d", charLen)
	}

	strBytes, err := p.reader.ReadAt(start+headerLen, int(charLen)*2)
	if err != nil || len(strBytes) < int(charLen)*2 {
		return "", false, fmt.Errorf("read UTF-16 record bytes: %w", err)
	}

	return decodeUTF16BE(strBytes), true, nil
}

func (p *Parser) tryReadUTF16BEStringRecordV2(start int64) (string, bool, error) {
	const (
		headerLen = 0x1e
	)

	header, err := p.reader.ReadAt(start, headerLen)
	if err != nil || len(header) < headerLen {
		return "", false, fmt.Errorf("read UTF-16 v2 header: %w", err)
	}

	if stdbinary.BigEndian.Uint32(header[0:4]) != 2 {
		return "", false, errors.New("unexpected UTF-16 v2 field count")
	}
	if !bytes.Equal(header[4:10], []byte{0x00, 0x00, 0x0a, 0x01, 0x00, 0x12}) {
		return "", false, errors.New("unexpected UTF-16 v2 descriptor table")
	}

	totalLen := stdbinary.BigEndian.Uint64(header[0x12:0x1a])
	charLen := stdbinary.BigEndian.Uint32(header[0x1a:0x1e])
	if totalLen != 8+uint64(charLen)*2 {
		return "", false, fmt.Errorf("invalid UTF-16 v2 length: total=%d chars=%d", totalLen, charLen)
	}
	if charLen == 0 {
		return "", true, nil
	}
	if charLen > 1_000_000 {
		return "", false, fmt.Errorf("UTF-16 v2 record too large: chars=%d", charLen)
	}

	strBytes, err := p.reader.ReadAt(start+headerLen, int(charLen)*2)
	if err != nil || len(strBytes) < int(charLen)*2 {
		return "", false, fmt.Errorf("read UTF-16 v2 bytes: %w", err)
	}

	return decodeUTF16BE(strBytes), true, nil
}

func decodeUTF16BE(data []byte) string {
	if len(data)%2 != 0 {
		data = data[:len(data)-1]
	}

	units := make([]uint16, 0, len(data)/2)
	for i := 0; i+1 < len(data); i += 2 {
		u := stdbinary.BigEndian.Uint16(data[i : i+2])
		if u == 0 {
			break
		}
		units = append(units, u)
	}
	if len(units) == 0 {
		return ""
	}
	return string(utf16.Decode(units))
}

const (
	issueEvidenceScanLen         = 64 * 1024
	issueEvidenceMaxMessageSize  = 50 * 1024 * 1024
	issueEvidenceMaxTypedRecRead = 64 * 1024
	issueEvidenceMaxDepth        = 6
)

var issueEvidenceExportOptions = ExportOptions{
	IncludeBody: true,
	IncludeRaw:  true,
	MaxBodySize: 0,
}

func (p *Parser) extractIssueEvidence(evidencePtr int64) ([]ScannerIssueEvidence, string, string) {
	if evidencePtr <= 0 {
		return nil, "", ""
	}

	entryPtrs := p.resolveEvidenceEntryPointers(evidencePtr)
	if len(entryPtrs) == 0 {
		entryPtrs = []int64{evidencePtr}
	}

	var evidence []ScannerIssueEvidence
	var host, path string

	for _, entryPtr := range entryPtrs {
		reqMsg, respMsg := p.resolveRequestResponse(entryPtr)
		if reqMsg == nil && respMsg == nil {
			continue
		}

		evidence = append(evidence, ScannerIssueEvidence{
			Request:  convertIssueMessage(reqMsg),
			Response: convertIssueMessage(respMsg),
		})

		if host == "" || path == "" {
			msgHost, msgPath := extractHostAndPathFromMessage(reqMsg)
			if host == "" {
				host = msgHost
			}
			if path == "" {
				path = msgPath
			}
		}
	}

	return evidence, host, path
}

func convertIssueMessage(msg *HTTPMessage) *ExportedMessage {
	if msg == nil {
		return nil
	}
	return convertMessage(msg, issueEvidenceExportOptions)
}

func extractHostAndPathFromMessage(msg *HTTPMessage) (string, string) {
	if msg == nil || msg.StartLine == "" {
		return "", ""
	}

	if !isHTTPMethodStart(msg.StartLine) {
		return "", ""
	}

	entry := &HTTPEntry{}
	parseRequestLine(entry, msg.StartLine)
	extractHostFromHeaders(entry, msg.Headers)

	path := entry.Path
	if entry.QueryString != "" {
		path = path + "?" + entry.QueryString
	}

	return entry.Host, path
}

func (p *Parser) resolveEvidenceEntryPointers(evidencePtr int64) []int64 {
	count, vecPtr, err := p.readListWrapper(evidencePtr)
	if err != nil || count == 0 {
		return nil
	}

	ptrs, err := p.readPointerVector(vecPtr)
	if err != nil || len(ptrs) == 0 {
		return nil
	}

	if int(count) < len(ptrs) {
		ptrs = ptrs[:count]
	}

	var entries []int64
	for _, ptr := range ptrs {
		if ptr <= int64(HeaderSize) || ptr >= p.reader.Size() {
			continue
		}
		entries = append(entries, ptr)
	}
	return entries
}

func (p *Parser) resolveRequestResponse(entryPtr int64) (*HTTPMessage, *HTTPMessage) {
	visited := make(map[int64]struct{})
	msgs := p.collectHTTPMessages(entryPtr, visited, 0)

	var reqMsg *HTTPMessage
	var respMsg *HTTPMessage

	for _, msg := range msgs {
		if msg == nil || msg.StartLine == "" {
			continue
		}
		if strings.HasPrefix(msg.StartLine, "HTTP/") {
			if respMsg == nil {
				respMsg = msg
			}
			continue
		}
		if reqMsg == nil && isHTTPMethodStart(msg.StartLine) {
			reqMsg = msg
		}
	}

	return reqMsg, respMsg
}

func (p *Parser) collectHTTPMessages(offset int64, visited map[int64]struct{}, depth int) []*HTTPMessage {
	if offset <= 0 || depth > issueEvidenceMaxDepth {
		return nil
	}
	if _, ok := visited[offset]; ok {
		return nil
	}
	visited[offset] = struct{}{}

	var msgs []*HTTPMessage

	if msg := p.tryHTTPMessageFromUTF8Record(offset); msg != nil {
		msgs = append(msgs, msg)
	}
	if msg := p.tryHTTPMessageFromRawRecord(offset); msg != nil {
		msgs = append(msgs, msg)
	}

	if count, vecPtr, err := p.readListWrapper(offset); err == nil && count > 0 {
		ptrs, err := p.readPointerVector(vecPtr)
		if err == nil {
			if int(count) < len(ptrs) {
				ptrs = ptrs[:count]
			}
			for _, ptr := range ptrs {
				msgs = append(msgs, p.collectHTTPMessages(ptr, visited, depth+1)...)
			}
		}
	}

	if rec, err := p.readTypedRecordHeader(offset); err == nil {
		ptrs := p.readTypedRecordPointers(offset, rec)
		for _, ptr := range ptrs {
			msgs = append(msgs, p.collectHTTPMessages(ptr, visited, depth+1)...)
		}
	}

	return msgs
}

func (p *Parser) tryHTTPMessageFromUTF8Record(offset int64) *HTTPMessage {
	s, err := p.readUTF8StringRecord(offset)
	if err != nil || s == "" {
		return nil
	}

	msg := parseHTTPMessage([]byte(s))
	if msg == nil || msg.StartLine == "" {
		return nil
	}
	if !looksLikeHTTPStartLine(msg.StartLine) {
		return nil
	}
	return msg
}

func (p *Parser) tryHTTPMessageFromRawRecord(offset int64) *HTTPMessage {
	if offset <= 0 {
		return nil
	}

	chunk, err := p.reader.ReadAt(offset, issueEvidenceScanLen)
	if err != nil || len(chunk) < 16 {
		return nil
	}

	start := findHTTPMessageStart(chunk)
	if start < 8 {
		return nil
	}

	totalLen := stdbinary.BigEndian.Uint32(chunk[start-8 : start-4])
	dataLen := stdbinary.BigEndian.Uint32(chunk[start-4 : start])
	if totalLen != dataLen+8 || dataLen == 0 {
		return nil
	}
	if dataLen > issueEvidenceMaxMessageSize {
		return nil
	}
	if offset+int64(start)+int64(dataLen) > p.reader.Size() {
		return nil
	}

	data, err := p.reader.ReadAt(offset+int64(start), int(dataLen))
	if err != nil || len(data) < int(dataLen) {
		return nil
	}

	msg := parseHTTPMessage(data)
	if msg == nil || msg.StartLine == "" {
		return nil
	}
	if !looksLikeHTTPStartLine(msg.StartLine) {
		return nil
	}
	return msg
}

func findHTTPMessageStart(chunk []byte) int {
	start := -1

	patterns := make([][]byte, 0, len(httpMethodPatterns)+1)
	patterns = append(patterns, httpMethodPatterns...)
	patterns = append(patterns, []byte("HTTP/"))

	for _, pat := range patterns {
		pos := bytes.Index(chunk, pat)
		if pos == -1 {
			continue
		}
		if start == -1 || pos < start {
			start = pos
		}
	}

	return start
}

func (p *Parser) readTypedRecordPointers(offset int64, rec typedRecord) []int64 {
	if len(rec.Fields) == 0 {
		return nil
	}

	maxOffset := 0
	for _, f := range rec.Fields {
		if int(f.Offset) > maxOffset {
			maxOffset = int(f.Offset)
		}
	}

	readLen := maxOffset + 8
	if readLen <= 0 || readLen > issueEvidenceMaxTypedRecRead {
		return nil
	}

	buf, err := p.reader.ReadAt(offset, readLen)
	if err != nil || len(buf) < readLen {
		return nil
	}

	var ptrs []int64
	for _, f := range rec.Fields {
		off := int(f.Offset)
		if off+8 > len(buf) {
			continue
		}
		ptr := int64(stdbinary.BigEndian.Uint64(buf[off : off+8]))
		if ptr <= int64(HeaderSize) || ptr >= p.reader.Size() {
			continue
		}
		ptrs = append(ptrs, ptr)
	}

	return ptrs
}

func looksLikeHTTPStartLine(line string) bool {
	if strings.HasPrefix(line, "HTTP/") {
		return true
	}
	return isHTTPMethodStart(line)
}

func isHTTPMethodStart(line string) bool {
	for _, pat := range httpMethodPatterns {
		if strings.HasPrefix(line, string(pat)) {
			return true
		}
	}
	return false
}

func (p *Parser) extractHostAndPathFromRequestRecord(recordOffset int64) (string, string) {
	if recordOffset <= 0 {
		return "", ""
	}

	const scanLen = 64 * 1024
	chunk, err := p.reader.ReadAt(recordOffset, scanLen)
	if err != nil || len(chunk) < 32 {
		return "", ""
	}

	methodPos := -1
	for _, pat := range httpMethodPatterns {
		pos := bytes.Index(chunk, pat)
		if pos == -1 {
			continue
		}
		if methodPos == -1 || pos < methodPos {
			methodPos = pos
		}
	}
	if methodPos < 8 {
		return "", ""
	}

	totalLen := stdbinary.BigEndian.Uint32(chunk[methodPos-8 : methodPos-4])
	dataLen := stdbinary.BigEndian.Uint32(chunk[methodPos-4 : methodPos])
	if totalLen != dataLen+8 || dataLen == 0 {
		return "", ""
	}

	reqBytes, err := p.reader.ReadAt(recordOffset+int64(methodPos), int(dataLen))
	if err != nil || len(reqBytes) == 0 {
		return "", ""
	}

	msg := parseHTTPMessage(reqBytes)
	if msg == nil || msg.StartLine == "" {
		return "", ""
	}

	entry := &HTTPEntry{}
	parseRequestLine(entry, msg.StartLine)
	extractHostFromHeaders(entry, msg.Headers)

	path := entry.Path
	if entry.QueryString != "" {
		path = path + "?" + entry.QueryString
	}

	return entry.Host, path
}
