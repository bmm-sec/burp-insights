package burp

import (
	"net/http"
	"time"
)

type Project struct {
	FilePath    string
	Magic       uint32
	Version     uint32
	HTTPHistory []HTTPEntry
	SiteMap     *SiteMap
	Issues      []ScannerIssue
	Metadata    ProjectMetadata
}

type ProjectMetadata struct {
	CreatedAt   time.Time
	ModifiedAt  time.Time
	BurpVersion string
	FileSize    int64
	RecordCount int
}

type HTTPEntry struct {
	ID            uint64
	Timestamp     time.Time
	Host          string
	Port          int
	Protocol      string
	Method        string
	Path          string
	QueryString   string
	URL           string
	Request       *HTTPMessage
	Response      *HTTPMessage
	StatusCode    int
	ContentLength int64
	MIMEType      string
	ToolSource    ToolType
	Comment       string
	Highlight     string
}

type HTTPMessage struct {
	Raw       []byte
	Headers   http.Header
	Body      []byte
	StartLine string
}

type SiteMapNode struct {
	Host     string
	Path     string
	Children map[string]*SiteMapNode
	Entries  []*HTTPEntry
}

type SiteMap struct {
	Root map[string]*SiteMapNode
}

type ScannerIssue struct {
	ID          uint64
	Name        string
	Severity    Severity
	Confidence  Confidence
	Host        string
	Path        string
	URL         string
	Description string
	Remediation string
	References  []string
	Evidence    []*HTTPEntry
}

type Severity int

const (
	SeverityInfo Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
)

func (s Severity) String() string {
	switch s {
	case SeverityInfo:
		return "Information"
	case SeverityLow:
		return "Low"
	case SeverityMedium:
		return "Medium"
	case SeverityHigh:
		return "High"
	default:
		return "Unknown"
	}
}

type Confidence int

const (
	ConfidenceTentative Confidence = iota
	ConfidenceFirm
	ConfidenceCertain
)

func (c Confidence) String() string {
	switch c {
	case ConfidenceTentative:
		return "Tentative"
	case ConfidenceFirm:
		return "Firm"
	case ConfidenceCertain:
		return "Certain"
	default:
		return "Unknown"
	}
}

type ToolType int

const (
	ToolUnknown ToolType = iota
	ToolProxy
	ToolRepeater
	ToolScanner
	ToolIntruder
	ToolSpider
	ToolSequencer
	ToolExtension
	ToolTarget
)

func (t ToolType) String() string {
	switch t {
	case ToolProxy:
		return "Proxy"
	case ToolRepeater:
		return "Repeater"
	case ToolScanner:
		return "Scanner"
	case ToolIntruder:
		return "Intruder"
	case ToolSpider:
		return "Spider"
	case ToolSequencer:
		return "Sequencer"
	case ToolExtension:
		return "Extension"
	case ToolTarget:
		return "Target"
	default:
		return "Unknown"
	}
}

type RepeaterTab struct {
	Name     string
	Request  *HTTPMessage
	Response *HTTPMessage
	Host     string
	Port     int
	Protocol string
}
