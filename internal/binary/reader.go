package binary

import (
	"encoding/binary"
	"errors"
	"io"
	"os"
)

var (
	ErrInvalidOffset = errors.New("invalid offset")
	ErrReadFailed    = errors.New("read failed")
)

type Reader struct {
	file      *os.File
	size      int64
	byteOrder binary.ByteOrder
}

func NewReader(path string) (*Reader, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	stat, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}

	return &Reader{
		file:      f,
		size:      stat.Size(),
		byteOrder: binary.BigEndian,
	}, nil
}

func (r *Reader) Close() error {
	if r.file != nil {
		return r.file.Close()
	}
	return nil
}

func (r *Reader) Size() int64 {
	return r.size
}

func (r *Reader) ReadAt(offset int64, length int) ([]byte, error) {
	if offset < 0 || offset >= r.size {
		return nil, ErrInvalidOffset
	}

	buf := make([]byte, length)
	n, err := r.file.ReadAt(buf, offset)
	if err != nil && err != io.EOF {
		return nil, err
	}

	return buf[:n], nil
}

func (r *Reader) ReadUint16At(offset int64) (uint16, error) {
	buf, err := r.ReadAt(offset, 2)
	if err != nil {
		return 0, err
	}
	if len(buf) < 2 {
		return 0, ErrReadFailed
	}
	return r.byteOrder.Uint16(buf), nil
}

func (r *Reader) ReadUint32At(offset int64) (uint32, error) {
	buf, err := r.ReadAt(offset, 4)
	if err != nil {
		return 0, err
	}
	if len(buf) < 4 {
		return 0, ErrReadFailed
	}
	return r.byteOrder.Uint32(buf), nil
}

func (r *Reader) ReadUint64At(offset int64) (uint64, error) {
	buf, err := r.ReadAt(offset, 8)
	if err != nil {
		return 0, err
	}
	if len(buf) < 8 {
		return 0, ErrReadFailed
	}
	return r.byteOrder.Uint64(buf), nil
}

func (r *Reader) FindPattern(pattern []byte, startOffset int64) (int64, error) {
	if len(pattern) == 0 {
		return -1, errors.New("empty pattern")
	}

	bufSize := 64 * 1024
	buf := make([]byte, bufSize+len(pattern)-1)
	offset := startOffset

	for offset < r.size {
		n, err := r.file.ReadAt(buf, offset)
		if err != nil && err != io.EOF {
			return -1, err
		}
		if n == 0 {
			break
		}

		for i := 0; i <= n-len(pattern); i++ {
			if matchPattern(buf[i:i+len(pattern)], pattern) {
				return offset + int64(i), nil
			}
		}

		offset += int64(bufSize)
	}

	return -1, nil
}

func (r *Reader) FindAllPatterns(pattern []byte, startOffset int64, maxResults int) ([]int64, error) {
	if len(pattern) == 0 {
		return nil, errors.New("empty pattern")
	}

	var results []int64
	bufSize := 64 * 1024
	buf := make([]byte, bufSize+len(pattern)-1)
	offset := startOffset

	for offset < r.size {
		if maxResults > 0 && len(results) >= maxResults {
			break
		}

		n, err := r.file.ReadAt(buf, offset)
		if err != nil && err != io.EOF {
			return nil, err
		}
		if n == 0 {
			break
		}

		for i := 0; i <= n-len(pattern); i++ {
			if matchPattern(buf[i:i+len(pattern)], pattern) {
				results = append(results, offset+int64(i))
				if maxResults > 0 && len(results) >= maxResults {
					break
				}
			}
		}

		offset += int64(bufSize)
	}

	return results, nil
}

func matchPattern(data, pattern []byte) bool {
	if len(data) < len(pattern) {
		return false
	}
	for i := range pattern {
		if data[i] != pattern[i] {
			return false
		}
	}
	return true
}

func (r *Reader) ReadUntil(offset int64, delimiter byte, maxLen int) ([]byte, error) {
	buf := make([]byte, maxLen)
	n, err := r.file.ReadAt(buf, offset)
	if err != nil && err != io.EOF {
		return nil, err
	}

	for i := 0; i < n; i++ {
		if buf[i] == delimiter {
			return buf[:i], nil
		}
	}

	return buf[:n], nil
}

func (r *Reader) ReadLine(offset int64, maxLen int) ([]byte, error) {
	buf, err := r.ReadUntil(offset, '\n', maxLen)
	if err != nil {
		return nil, err
	}
	if len(buf) > 0 && buf[len(buf)-1] == '\r' {
		buf = buf[:len(buf)-1]
	}
	return buf, nil
}
