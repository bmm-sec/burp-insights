package burp

import (
	"bytes"
	stdbinary "encoding/binary"
	"errors"
	"fmt"
	"strings"
)

type UITask struct {
	ID    int64  `json:"id"`
	Type  uint16 `json:"type"`
	Name  string `json:"name"`
	Scope string `json:"scope,omitempty"`
}

func (p *Parser) ScanUITasks() ([]UITask, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	const (
		uiTasksListOffset = 0x1f4
		maxTaskCount      = 256
	)

	count, vecPtr, err := p.readListWrapper(uiTasksListOffset)
	if err != nil {
		return nil, fmt.Errorf("read UI tasks list wrapper at 0x%x: %w", uiTasksListOffset, err)
	}
	if count == 0 {
		return nil, nil
	}
	if count > maxTaskCount {
		return nil, fmt.Errorf("UI tasks list count too large: %d", count)
	}

	ptrs, err := p.readPointerVector(vecPtr)
	if err != nil {
		return nil, fmt.Errorf("read UI tasks pointer vector at 0x%x: %w", vecPtr, err)
	}
	if uint32(len(ptrs)) < count {
		return nil, fmt.Errorf("UI tasks vector too small: have=%d need=%d", len(ptrs), count)
	}

	tasks := make([]UITask, 0, count)
	for i := uint32(0); i < count; i++ {
		taskPtr := ptrs[i]
		if taskPtr <= 0 {
			return nil, fmt.Errorf("invalid task pointer at index=%d: 0x%x", i, taskPtr)
		}

		rec, err := p.readTypedRecordHeader(taskPtr)
		if err != nil {
			return nil, fmt.Errorf("read task record header at 0x%x: %w", taskPtr, err)
		}

		taskIndex := int(i) + 1
		scope, displayName, err := p.buildUITaskDisplayName(taskPtr, rec, taskIndex)
		if err != nil {
			return nil, fmt.Errorf("build task name at 0x%x: %w", taskPtr, err)
		}

		tasks = append(tasks, UITask{
			ID:    taskPtr,
			Type:  rec.Type,
			Name:  displayName,
			Scope: scope,
		})
	}

	return tasks, nil
}

func (p *Parser) buildUITaskDisplayName(taskPtr int64, rec typedRecord, taskIndex int) (scope string, displayName string, _ error) {
	scope, _ = p.readScopeStringFromUITaskRecord(taskPtr, rec)

	switch rec.Type {
	case 4:
		if scope == "" {
			return "", "", errors.New("unable to locate task scope string")
		}
		return scope, fmt.Sprintf("%d. Live passive crawl from %s", taskIndex, scope), nil
	case 5:
		if scope == "" {
			return "", "", errors.New("unable to locate task scope string")
		}
		return scope, fmt.Sprintf("%d. Live audit from %s", taskIndex, scope), nil
	case 2, 3:
		custom, _ := p.readCustomNameFromUITaskRecord(taskPtr, rec)
		if custom == "" {
			return scope, fmt.Sprintf("%d. Custom task", taskIndex), nil
		}
		if hasNumericPrefix(custom) {
			return scope, custom, nil
		}
		return scope, fmt.Sprintf("%d. %s", taskIndex, custom), nil
	default:
		if scope != "" {
			return scope, fmt.Sprintf("%d. Task (type=%d) %s", taskIndex, rec.Type, scope), nil
		}
		return "", fmt.Sprintf("%d. Task (type=%d)", taskIndex, rec.Type), nil
	}
}

func hasNumericPrefix(s string) bool {
	if len(s) < 3 {
		return false
	}
	if s[0] < '0' || s[0] > '9' {
		return false
	}
	return strings.HasPrefix(s[1:], ". ")
}

func (p *Parser) readListWrapper(offset int64) (count uint32, vecPtr int64, _ error) {
	const (
		headerLen = 10
		countOff  = 0x0a
		vecPtrOff = 0x0e
		readLen   = vecPtrOff + 8
		maxVecPtr = int64(^uint64(0) >> 1)
	)

	listWrapperSig := []byte{0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x0a, 0x01, 0x00, 0x0e}

	buf, err := p.reader.ReadAt(offset, readLen)
	if err != nil || len(buf) < readLen {
		return 0, 0, fmt.Errorf("read list wrapper: %w", err)
	}
	if !bytes.Equal(buf[:headerLen], listWrapperSig) {
		return 0, 0, errors.New("unexpected list wrapper signature")
	}

	count = stdbinary.BigEndian.Uint32(buf[countOff : countOff+4])
	ptr := stdbinary.BigEndian.Uint64(buf[vecPtrOff : vecPtrOff+8])
	if ptr == 0 || ptr > uint64(maxVecPtr) {
		return 0, 0, errors.New("invalid list wrapper vector pointer")
	}
	vecPtr = int64(ptr)
	return count, vecPtr, nil
}

func (p *Parser) readPointerVector(offset int64) ([]int64, error) {
	const maxCap = 1_000_000

	buf, err := p.reader.ReadAt(offset, 8)
	if err != nil || len(buf) < 8 {
		return nil, fmt.Errorf("read pointer vector header: %w", err)
	}

	totalLen := stdbinary.BigEndian.Uint32(buf[:4])
	capacity := stdbinary.BigEndian.Uint32(buf[4:8])
	if capacity == 0 || capacity > maxCap {
		return nil, fmt.Errorf("invalid pointer vector capacity: %d", capacity)
	}

	expectedTotal := uint32(8 + capacity*8)
	if totalLen != expectedTotal {
		return nil, fmt.Errorf("invalid pointer vector length: total=%d expected=%d", totalLen, expectedTotal)
	}

	data, err := p.reader.ReadAt(offset+8, int(capacity*8))
	if err != nil || len(data) < int(capacity*8) {
		return nil, fmt.Errorf("read pointer vector data: %w", err)
	}

	ptrs := make([]int64, 0, capacity)
	for i := uint32(0); i < capacity; i++ {
		raw := stdbinary.BigEndian.Uint64(data[i*8 : i*8+8])
		ptrs = append(ptrs, int64(raw))
	}

	return ptrs, nil
}

type typedRecordField struct {
	ID     byte
	Offset uint16
}

type typedRecord struct {
	Type       uint16
	FieldCount uint16
	Fields     []typedRecordField
}

func (r typedRecord) fieldOffset(id byte) (uint16, bool) {
	for _, f := range r.Fields {
		if f.ID == id {
			return f.Offset, true
		}
	}
	return 0, false
}

func (p *Parser) readTypedRecordHeader(offset int64) (typedRecord, error) {
	const maxFieldCount = 256

	hdr, err := p.reader.ReadAt(offset, 4)
	if err != nil || len(hdr) < 4 {
		return typedRecord{}, fmt.Errorf("read record header: %w", err)
	}

	recType := stdbinary.BigEndian.Uint16(hdr[0:2])
	fieldCount := stdbinary.BigEndian.Uint16(hdr[2:4])
	if fieldCount == 0 {
		return typedRecord{}, errors.New("invalid typed record field count: 0")
	}
	if fieldCount > maxFieldCount {
		return typedRecord{}, fmt.Errorf("typed record field count too large: %d", fieldCount)
	}

	descLen := int(fieldCount) * 3
	desc, err := p.reader.ReadAt(offset+4, descLen)
	if err != nil || len(desc) < descLen {
		return typedRecord{}, fmt.Errorf("read typed record descriptor table: %w", err)
	}

	headerLen := uint16(4 + descLen)
	fields := make([]typedRecordField, 0, fieldCount)
	var prev uint16
	for i := 0; i < int(fieldCount); i++ {
		fieldID := desc[i*3]
		off := stdbinary.BigEndian.Uint16(desc[i*3+1 : i*3+3])
		if off < headerLen {
			return typedRecord{}, fmt.Errorf("invalid typed record field offset: field=0x%x off=0x%x header=0x%x", fieldID, off, headerLen)
		}
		if i == 0 && off != headerLen {
			return typedRecord{}, fmt.Errorf("unexpected typed record first field offset: have=0x%x want=0x%x", off, headerLen)
		}
		if i > 0 && off < prev {
			return typedRecord{}, errors.New("typed record offsets not ascending")
		}
		prev = off
		fields = append(fields, typedRecordField{ID: fieldID, Offset: off})
	}

	return typedRecord{
		Type:       recType,
		FieldCount: fieldCount,
		Fields:     fields,
	}, nil
}

func (p *Parser) readCustomNameFromUITaskRecord(taskPtr int64, rec typedRecord) (string, error) {
	fieldOff, ok := rec.fieldOffset(0x08)
	if !ok {
		return "", errors.New("missing task name field (0x08)")
	}

	ptr, err := p.readPointerAt(taskPtr + int64(fieldOff))
	if err != nil {
		return "", err
	}

	name, err := p.readUTF16BEStringRecord(ptr)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(name), nil
}

func (p *Parser) readScopeStringFromUITaskRecord(taskPtr int64, rec typedRecord) (string, error) {
	fieldOff, ok := rec.fieldOffset(0x02)
	if !ok {
		return "", errors.New("missing task scope container field (0x02)")
	}

	scopeContainerPtr, err := p.readPointerAt(taskPtr + int64(fieldOff))
	if err != nil {
		return "", err
	}

	scopeListPtr, err := p.readScopeListWrapperPtr(scopeContainerPtr)
	if err != nil {
		return "", err
	}

	count, vecPtr, err := p.readListWrapper(scopeListPtr)
	if err != nil {
		return "", err
	}
	if count == 0 {
		return "", nil
	}

	ptrs, err := p.readPointerVector(vecPtr)
	if err != nil {
		return "", err
	}
	if uint32(len(ptrs)) < count {
		return "", errors.New("scope pointer vector shorter than list count")
	}

	scopeRawPtr := ptrs[0]
	if scopeRawPtr <= 0 {
		return "", errors.New("invalid scope string pointer")
	}
	scope, err := p.readFixedUTF16BEStringRecord32(scopeRawPtr)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(scope), nil
}

func (p *Parser) readScopeListWrapperPtr(scopeContainerPtr int64) (int64, error) {
	rec, err := p.readV2RecordHeader(scopeContainerPtr)
	if err != nil {
		return 0, fmt.Errorf("read scope container record at 0x%x: %w", scopeContainerPtr, err)
	}

	off, ok := rec.fieldOffset(3)
	if !ok {
		return 0, errors.New("scope container missing field 3")
	}

	ptr, err := p.readPointerAt(scopeContainerPtr + int64(off))
	if err != nil {
		return 0, err
	}
	return ptr, nil
}

type v2Record struct {
	FieldCount uint32
	Fields     []typedRecordField
}

func (r v2Record) fieldOffset(id byte) (uint16, bool) {
	for _, f := range r.Fields {
		if f.ID == id {
			return f.Offset, true
		}
	}
	return 0, false
}

func (p *Parser) readV2RecordHeader(offset int64) (v2Record, error) {
	const maxFieldCount = 10_000

	hdr, err := p.reader.ReadAt(offset, 4)
	if err != nil || len(hdr) < 4 {
		return v2Record{}, fmt.Errorf("read record header: %w", err)
	}
	fieldCount := stdbinary.BigEndian.Uint32(hdr)
	if fieldCount == 0 {
		return v2Record{}, errors.New("invalid v2 record field count: 0")
	}
	if fieldCount > maxFieldCount {
		return v2Record{}, fmt.Errorf("v2 record field count too large: %d", fieldCount)
	}

	descLen := int(fieldCount) * 3
	desc, err := p.reader.ReadAt(offset+4, descLen)
	if err != nil || len(desc) < descLen {
		return v2Record{}, fmt.Errorf("read v2 descriptor table: %w", err)
	}

	headerLen := uint16(4 + descLen)
	fields := make([]typedRecordField, 0, fieldCount)
	var prev uint16
	for i := 0; i < int(fieldCount); i++ {
		fieldID := desc[i*3]
		off := stdbinary.BigEndian.Uint16(desc[i*3+1 : i*3+3])
		if off < headerLen {
			return v2Record{}, fmt.Errorf("invalid v2 record field offset: field=%d off=0x%x header=0x%x", fieldID, off, headerLen)
		}
		if i == 0 && off != headerLen {
			return v2Record{}, fmt.Errorf("unexpected v2 record first field offset: have=0x%x want=0x%x", off, headerLen)
		}
		if i > 0 && off < prev {
			return v2Record{}, errors.New("v2 record offsets not ascending")
		}
		prev = off
		fields = append(fields, typedRecordField{ID: fieldID, Offset: off})
	}

	return v2Record{
		FieldCount: fieldCount,
		Fields:     fields,
	}, nil
}

func (p *Parser) readPointerAt(offset int64) (int64, error) {
	raw, err := p.reader.ReadUint64At(offset)
	if err != nil {
		return 0, err
	}
	ptr := int64(raw)
	if ptr <= 0 || ptr >= p.reader.Size() {
		return 0, errors.New("invalid pointer value")
	}
	return ptr, nil
}

func (p *Parser) readFixedUTF16BEStringRecord32(ptr int64) (string, error) {
	candidates := []int64{ptr, ptr + 2, ptr - 2}
	for _, start := range candidates {
		s, ok, err := p.tryReadFixedUTF16BEStringRecord32(start)
		if err != nil {
			continue
		}
		if ok {
			return s, nil
		}
	}
	return "", errors.New("unable to parse fixed UTF-16 string record")
}

func (p *Parser) tryReadFixedUTF16BEStringRecord32(offset int64) (string, bool, error) {
	if offset <= 0 || offset+8 > p.reader.Size() {
		return "", false, errors.New("invalid offset")
	}

	hdr, err := p.reader.ReadAt(offset, 8)
	if err != nil || len(hdr) < 8 {
		return "", false, err
	}

	totalLen := stdbinary.BigEndian.Uint32(hdr[0:4])
	charLen := stdbinary.BigEndian.Uint32(hdr[4:8])
	if totalLen != 0x48 || charLen != 0x20 {
		return "", false, nil
	}

	data, err := p.reader.ReadAt(offset+8, int(charLen)*2)
	if err != nil || len(data) < int(charLen)*2 {
		return "", false, err
	}
	return decodeUTF16BE(data), true, nil
}
