package burp

import (
	stdbinary "encoding/binary"
	"sort"
)

type ScannerTaskSummary struct {
	TaskID           uint64         `json:"taskId"`
	Host             string         `json:"host,omitempty"`
	Port             uint32         `json:"port,omitempty"`
	Secure           bool           `json:"secure,omitempty"`
	Timestamp        uint64         `json:"timestamp,omitempty"`
	IssueCount       int            `json:"issueCount"`
	SeverityCounts   map[string]int `json:"severityCounts,omitempty"`
	ConfidenceCounts map[string]int `json:"confidenceCounts,omitempty"`
	UniqueIssueTypes int            `json:"uniqueIssueTypes,omitempty"`
}

func (p *Parser) ScanScannerTaskSummaries(filterSerialNumbers map[uint64]struct{}) ([]ScannerTaskSummary, error) {
	metas, err := p.ScanScannerIssueMetas(filterSerialNumbers)
	if err != nil {
		return nil, err
	}

	byTask := make(map[uint64]*ScannerTaskSummary)
	typeSets := make(map[uint64]map[uint32]struct{})

	for _, meta := range metas {
		summary, ok := byTask[meta.TaskID]
		if !ok {
			summary = &ScannerTaskSummary{
				TaskID:           meta.TaskID,
				SeverityCounts:   make(map[string]int),
				ConfidenceCounts: make(map[string]int),
			}
			byTask[meta.TaskID] = summary
			typeSets[meta.TaskID] = make(map[uint32]struct{})
		}

		summary.IssueCount++
		summary.SeverityCounts[meta.Severity.String()]++
		summary.ConfidenceCounts[meta.Confidence.String()]++
		typeSets[meta.TaskID][meta.Type] = struct{}{}
	}

	summaries := make([]ScannerTaskSummary, 0, len(byTask))
	for taskID, summary := range byTask {
		summary.UniqueIssueTypes = len(typeSets[taskID])
		p.populateScannerTaskMetadata(summary)
		summaries = append(summaries, *summary)
	}

	sort.Slice(summaries, func(i, j int) bool {
		if summaries[i].IssueCount != summaries[j].IssueCount {
			return summaries[i].IssueCount > summaries[j].IssueCount
		}
		return summaries[i].TaskID < summaries[j].TaskID
	})

	return summaries, nil
}

func (p *Parser) populateScannerTaskMetadata(summary *ScannerTaskSummary) {
	if summary == nil || summary.TaskID == 0 {
		return
	}

	const (
		taskSigLen = 4 + 7*3
		needLen    = 0x2f + 8

		hostPtrOff  = 0x19
		portOff     = 0x21
		secureOff   = 0x25
		timestampOff = 0x27
	)

	taskSig := []byte{
		0x00, 0x00, 0x00, 0x07,
		0x00, 0x00, 0x19,
		0x01, 0x00, 0x21,
		0x02, 0x00, 0x25,
		0x03, 0x00, 0x26,
		0x04, 0x00, 0x27,
		0x05, 0x00, 0x2f,
		0x06, 0x00, 0x37,
	}

	abs := int64(summary.TaskID)
	rec, err := p.reader.ReadAt(abs, needLen)
	if err != nil || len(rec) < needLen {
		return
	}
	if len(rec) < taskSigLen || !bytesEqual(rec[:taskSigLen], taskSig) {
		return
	}

	hostPtr := int64(stdbinary.BigEndian.Uint64(rec[hostPtrOff : hostPtrOff+8]))
	port := stdbinary.BigEndian.Uint32(rec[portOff : portOff+4])
	secureFlag := rec[secureOff]
	ts := stdbinary.BigEndian.Uint64(rec[timestampOff : timestampOff+8])

	host, _ := p.readUTF16BEStringRecord(hostPtr)

	summary.Host = host
	summary.Port = port
	summary.Secure = secureFlag == 1
	summary.Timestamp = ts
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
