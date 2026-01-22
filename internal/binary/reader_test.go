package binary

import (
	"encoding/binary"
	"os"
	"testing"
)

func createTempFile(t *testing.T, data []byte) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "reader-*.bin")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	if _, err := f.Write(data); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close temp file: %v", err)
	}
	return f.Name()
}

func TestReaderReadAtAndUint(t *testing.T) {
	data := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	path := createTempFile(t, data)

	r, err := NewReader(path)
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	defer r.Close()

	buf, err := r.ReadAt(1, 3)
	if err != nil {
		t.Fatalf("ReadAt: %v", err)
	}
	if len(buf) != 3 || buf[0] != 0x01 {
		t.Fatalf("unexpected ReadAt result: %#v", buf)
	}

	if _, err := r.ReadAt(-1, 2); err != ErrInvalidOffset {
		t.Fatalf("expected ErrInvalidOffset, got %v", err)
	}

	val16, err := r.ReadUint16At(0)
	if err != nil {
		t.Fatalf("ReadUint16At: %v", err)
	}
	if val16 != binary.BigEndian.Uint16(data[:2]) {
		t.Fatalf("unexpected uint16: %d", val16)
	}
}

func TestReaderReadUintErrors(t *testing.T) {
	path := createTempFile(t, []byte{0x00, 0x01, 0x02})
	r, err := NewReader(path)
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	defer r.Close()

	if _, err := r.ReadUint32At(1); err != ErrReadFailed {
		t.Fatalf("expected ErrReadFailed, got %v", err)
	}
	if _, err := r.ReadUint64At(1); err != ErrReadFailed {
		t.Fatalf("expected ErrReadFailed, got %v", err)
	}
}

func TestReaderFindPatterns(t *testing.T) {
	data := []byte("hello world hello")
	path := createTempFile(t, data)
	r, err := NewReader(path)
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	defer r.Close()

	pos, err := r.FindPattern([]byte("world"), 0)
	if err != nil {
		t.Fatalf("FindPattern: %v", err)
	}
	if pos != 6 {
		t.Fatalf("expected position 6, got %d", pos)
	}

	all, err := r.FindAllPatterns([]byte("hello"), 0, 0)
	if err != nil {
		t.Fatalf("FindAllPatterns: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("expected 2 matches, got %d", len(all))
	}

	limited, err := r.FindAllPatterns([]byte("hello"), 0, 1)
	if err != nil {
		t.Fatalf("FindAllPatterns: %v", err)
	}
	if len(limited) != 1 {
		t.Fatalf("expected 1 match, got %d", len(limited))
	}
}

func TestReaderReadUntilAndLine(t *testing.T) {
	data := []byte("line1\r\nline2\n")
	path := createTempFile(t, data)
	r, err := NewReader(path)
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	defer r.Close()

	buf, err := r.ReadUntil(0, '\n', 10)
	if err != nil {
		t.Fatalf("ReadUntil: %v", err)
	}
	if string(buf) != "line1\r" {
		t.Fatalf("unexpected ReadUntil: %q", string(buf))
	}

	line, err := r.ReadLine(0, 10)
	if err != nil {
		t.Fatalf("ReadLine: %v", err)
	}
	if string(line) != "line1" {
		t.Fatalf("unexpected ReadLine: %q", string(line))
	}
}

func TestMatchPattern(t *testing.T) {
	if !matchPattern([]byte{1, 2, 3}, []byte{1, 2}) {
		t.Fatal("expected match")
	}
	if matchPattern([]byte{1}, []byte{1, 2}) {
		t.Fatal("expected no match")
	}
}
