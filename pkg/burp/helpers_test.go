package burp

import "testing"

func TestSeverityFromBurpByte(t *testing.T) {
	cases := []struct {
		b     byte
		want  Severity
		ok    bool
	}{
		{1, SeverityInfo, true},
		{2, SeverityLow, true},
		{3, SeverityMedium, true},
		{4, SeverityHigh, true},
		{99, SeverityInfo, false},
	}

	for _, tc := range cases {
		got, ok := severityFromBurpByte(tc.b)
		if got != tc.want || ok != tc.ok {
			t.Fatalf("severityFromBurpByte(%d) = %v,%v want %v,%v", tc.b, got, ok, tc.want, tc.ok)
		}
	}
}

func TestConfidenceFromBurpByte(t *testing.T) {
	cases := []struct {
		b     byte
		want  Confidence
		ok    bool
	}{
		{1, ConfidenceTentative, true},
		{2, ConfidenceFirm, true},
		{3, ConfidenceCertain, true},
		{99, ConfidenceTentative, false},
	}

	for _, tc := range cases {
		got, ok := confidenceFromBurpByte(tc.b)
		if got != tc.want || ok != tc.ok {
			t.Fatalf("confidenceFromBurpByte(%d) = %v,%v want %v,%v", tc.b, got, ok, tc.want, tc.ok)
		}
	}
}

func TestHasNumericPrefix(t *testing.T) {
	if !hasNumericPrefix("1. Task") {
		t.Fatal("expected numeric prefix to match")
	}
	if hasNumericPrefix("Task 1") {
		t.Fatal("expected numeric prefix to reject")
	}
	if hasNumericPrefix("1") {
		t.Fatal("expected short numeric prefix to reject")
	}
}

func TestBytesEqual(t *testing.T) {
	if !bytesEqual([]byte{1, 2, 3}, []byte{1, 2, 3}) {
		t.Fatal("expected bytes to be equal")
	}
	if bytesEqual([]byte{1, 2}, []byte{1, 2, 3}) {
		t.Fatal("expected bytes to be different")
	}
}
