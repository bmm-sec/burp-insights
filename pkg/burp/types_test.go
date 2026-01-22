package burp

import "testing"

func TestSeverityString(t *testing.T) {
	cases := []struct {
		sev  Severity
		want string
	}{
		{SeverityInfo, "Information"},
		{SeverityLow, "Low"},
		{SeverityMedium, "Medium"},
		{SeverityHigh, "High"},
		{Severity(99), "Unknown"},
	}

	for _, tc := range cases {
		if got := tc.sev.String(); got != tc.want {
			t.Errorf("Severity(%d).String() = %q, want %q", tc.sev, got, tc.want)
		}
	}
}

func TestConfidenceString(t *testing.T) {
	cases := []struct {
		conf Confidence
		want string
	}{
		{ConfidenceTentative, "Tentative"},
		{ConfidenceFirm, "Firm"},
		{ConfidenceCertain, "Certain"},
		{Confidence(99), "Unknown"},
	}

	for _, tc := range cases {
		if got := tc.conf.String(); got != tc.want {
			t.Errorf("Confidence(%d).String() = %q, want %q", tc.conf, got, tc.want)
		}
	}
}

func TestToolTypeString(t *testing.T) {
	cases := []struct {
		tool ToolType
		want string
	}{
		{ToolProxy, "Proxy"},
		{ToolRepeater, "Repeater"},
		{ToolScanner, "Scanner"},
		{ToolIntruder, "Intruder"},
		{ToolSpider, "Spider"},
		{ToolSequencer, "Sequencer"},
		{ToolExtension, "Extension"},
		{ToolTarget, "Target"},
		{ToolUnknown, "Unknown"},
		{ToolType(42), "Unknown"},
	}

	for _, tc := range cases {
		if got := tc.tool.String(); got != tc.want {
			t.Errorf("ToolType(%d).String() = %q, want %q", tc.tool, got, tc.want)
		}
	}
}
