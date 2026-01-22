package burp

import "testing"

func TestIsHTTPResponseStart(t *testing.T) {
	tests := []struct {
		name string
		data string
		want bool
	}{
		{"http11_ok", "HTTP/1.1 200 OK", true},
		{"http10_notfound_crlf", "HTTP/1.0 404\r\n", true},
		{"http2_found", "HTTP/2 302 Found", true},
		{"http20_error", "HTTP/2.0 500", true},
		{"http3_nocontent", "HTTP/3 204", true},
		{"http30_teapot", "HTTP/3.0 418 I'm a teapot", true},
		{"tab_separated", "HTTP/1.1\t200\tOK", true},
		{"invalid_minor", "HTTP/1.2 200 OK", false},
		{"invalid_http2_minor", "HTTP/2.1 200 OK", false},
		{"missing_status", "HTTP/2", false},
		{"short_status", "HTTP/1.1 20", false},
		{"long_status", "HTTP/1.1 2000", false},
		{"missing_slash", "HTTP 200 OK", false},
		{"missing_version", "HTTP/ 200 OK", false},
		{"missing_delimiter", "HTTP/1.1 200OK", false},
		{"invalid_status_delim", "HTTP/1.1 200X", false},
		{"not_http", "NOTHTTP/1.1 200 OK", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := isHTTPResponseStart([]byte(tc.data))
			if got != tc.want {
				t.Fatalf("isHTTPResponseStart(%q) = %v, want %v", tc.data, got, tc.want)
			}
		})
	}
}

func TestFindHTTPResponseStart(t *testing.T) {
	tests := []struct {
		name string
		data string
		want int
	}{
		{"start_at_zero", "HTTP/1.1 200 OK", 0},
		{"start_after_prefix", "junk HTTP/1.0 404\r\n", 5},
		{"multiple_candidates", "xxHTTP/1.1 20 yy HTTP/2 200 OK", 17},
		{"no_match", "HTTP/1.1 20 OK", -1},
		{"too_short", "H", -1},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := findHTTPResponseStart([]byte(tc.data))
			if got != tc.want {
				t.Fatalf("findHTTPResponseStart(%q) = %d, want %d", tc.data, got, tc.want)
			}
		})
	}
}
