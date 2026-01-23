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

func TestParseRequestLine(t *testing.T) {
	tests := []struct {
		name       string
		line       string
		wantMethod string
		wantPath   string
		wantQuery  string
		wantHost   string
		wantPort   int
		wantProto  string
	}{
		{
			name:       "origin_form",
			line:       "GET /content/swagger/v1/swagger.json HTTP/1.1",
			wantMethod: "GET",
			wantPath:   "/content/swagger/v1/swagger.json",
			wantProto:  "HTTP/1.1",
		},
		{
			name:       "origin_form_query",
			line:       "GET /content/swagger/v1/swagger.json?x=1 HTTP/1.1",
			wantMethod: "GET",
			wantPath:   "/content/swagger/v1/swagger.json",
			wantQuery:  "x=1",
			wantProto:  "HTTP/1.1",
		},
		{
			name:       "absolute_form",
			line:       "GET https://api.example.com/content/swagger/v1/swagger.json?x=1 HTTP/1.1",
			wantMethod: "GET",
			wantPath:   "/content/swagger/v1/swagger.json",
			wantQuery:  "x=1",
			wantHost:   "api.example.com",
			wantPort:   443,
			wantProto:  "HTTP/1.1",
		},
		{
			name:       "absolute_form_default_path",
			line:       "GET http://example.com HTTP/1.1",
			wantMethod: "GET",
			wantPath:   "/",
			wantHost:   "example.com",
			wantPort:   80,
			wantProto:  "HTTP/1.1",
		},
		{
			name:       "connect_form",
			line:       "CONNECT api.example.com:443 HTTP/1.1",
			wantMethod: "CONNECT",
			wantPath:   "api.example.com:443",
			wantHost:   "api.example.com",
			wantPort:   443,
			wantProto:  "HTTP/1.1",
		},
		{
			name:       "asterisk_form",
			line:       "OPTIONS * HTTP/1.1",
			wantMethod: "OPTIONS",
			wantPath:   "*",
			wantProto:  "HTTP/1.1",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			entry := &HTTPEntry{}
			parseRequestLine(entry, tc.line)
			if entry.Method != tc.wantMethod {
				t.Fatalf("Method = %q, want %q", entry.Method, tc.wantMethod)
			}
			if entry.Path != tc.wantPath {
				t.Fatalf("Path = %q, want %q", entry.Path, tc.wantPath)
			}
			if entry.QueryString != tc.wantQuery {
				t.Fatalf("QueryString = %q, want %q", entry.QueryString, tc.wantQuery)
			}
			if entry.Host != tc.wantHost {
				t.Fatalf("Host = %q, want %q", entry.Host, tc.wantHost)
			}
			if entry.Port != tc.wantPort {
				t.Fatalf("Port = %d, want %d", entry.Port, tc.wantPort)
			}
			if entry.Protocol != tc.wantProto {
				t.Fatalf("Protocol = %q, want %q", entry.Protocol, tc.wantProto)
			}
		})
	}
}
