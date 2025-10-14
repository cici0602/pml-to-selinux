package mapping

import (
	"testing"
)

func TestPathMapper_ConvertToSELinuxPattern(t *testing.T) {
	tests := []struct {
		name            string
		casbinPath      string
		expectedPattern string
	}{
		{
			name:            "wildcard at end",
			casbinPath:      "/var/www/*",
			expectedPattern: "/var/www(/.*)?",
		},
		{
			name:            "wildcard in middle",
			casbinPath:      "/etc/*.conf",
			expectedPattern: "/etc/[^/]+\\\\.conf",
		},
		{
			name:            "nested directory wildcard",
			casbinPath:      "/var/log/httpd/*",
			expectedPattern: "/var/log/httpd(/.*)?",
		},
		{
			name:            "home directory pattern",
			casbinPath:      "/home/*/public_html",
			expectedPattern: "/home/[^/]+/public_html",
		},
		{
			name:            "no wildcard",
			casbinPath:      "/etc/httpd/conf/httpd.conf",
			expectedPattern: "/etc/httpd/conf/httpd\\\\.conf",
		},
		{
			name:            "multiple wildcards",
			casbinPath:      "/var/*/logs/*.log",
			expectedPattern: "/var/[^/]+/logs/[^/]+\\\\.log",
		},
	}

	mapper := NewPathMapper()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mapper.ConvertToSELinuxPattern(tt.casbinPath)
			if result != tt.expectedPattern {
				t.Errorf("ConvertToSELinuxPattern(%q) = %q, want %q",
					tt.casbinPath, result, tt.expectedPattern)
			}
		})
	}
}

func TestPathMapper_CustomMapping(t *testing.T) {
	mapper := NewPathMapper()
	mapper.AddCustomMapping("/custom/path/*", "/custom/path(/.+)?")

	result := mapper.ConvertToSELinuxPattern("/custom/path/*")
	expected := "/custom/path(/.+)?"

	if result != expected {
		t.Errorf("Custom mapping failed: got %q, want %q", result, expected)
	}
}

func TestPathMapper_InferFileType(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected string
	}{
		{
			name:     "directory with trailing slash",
			path:     "/var/www/",
			expected: "directory",
		},
		{
			name:     "wildcard path",
			path:     "/var/www/*",
			expected: "all files",
		},
		{
			name:     "config file",
			path:     "/etc/httpd.conf",
			expected: "regular file",
		},
		{
			name:     "log file",
			path:     "/var/log/httpd/access.log",
			expected: "regular file",
		},
		{
			name:     "html file",
			path:     "/var/www/index.html",
			expected: "regular file",
		},
		{
			name:     "generic path",
			path:     "/usr/local/bin/myapp",
			expected: "all files",
		},
	}

	mapper := NewPathMapper()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mapper.InferFileType(tt.path)
			if result != tt.expected {
				t.Errorf("InferFileType(%q) = %q, want %q",
					tt.path, result, tt.expected)
			}
		})
	}
}

func TestGetFileTypeSpecifier(t *testing.T) {
	tests := []struct {
		fileType string
		expected string
	}{
		{"regular file", " --"},
		{"directory", " -d"},
		{"symlink", " -l"},
		{"socket", " -s"},
		{"pipe", " -p"},
		{"block", " -b"},
		{"char", " -c"},
		{"all files", ""},
		{"unknown", ""},
	}

	for _, tt := range tests {
		t.Run(tt.fileType, func(t *testing.T) {
			result := GetFileTypeSpecifier(tt.fileType)
			if result != tt.expected {
				t.Errorf("GetFileTypeSpecifier(%q) = %q, want %q",
					tt.fileType, result, tt.expected)
			}
		})
	}
}

func TestPathMapper_ValidatePattern(t *testing.T) {
	mapper := NewPathMapper()

	validTests := []string{
		"/var/www(/.*)?",
		"/etc/[^/]+\\.conf",
		"/home/[a-z]+/public_html",
	}

	for _, pattern := range validTests {
		t.Run("valid_"+pattern, func(t *testing.T) {
			err := mapper.ValidatePattern(pattern)
			if err != nil {
				t.Errorf("ValidatePattern(%q) returned error: %v", pattern, err)
			}
		})
	}

	invalidTests := []struct {
		pattern string
		desc    string
	}{
		{"var/www/*", "missing leading slash"},
		{"/var/[unclosed", "invalid regex"},
	}

	for _, tt := range invalidTests {
		t.Run("invalid_"+tt.desc, func(t *testing.T) {
			err := mapper.ValidatePattern(tt.pattern)
			if err == nil {
				t.Errorf("ValidatePattern(%q) should return error for %s",
					tt.pattern, tt.desc)
			}
		})
	}
}

func TestNormalizePath(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"/var/www/", "/var/www"},
		{"/etc/", "/etc"},
		{"/", "/"},
		{"/var/log/httpd/", "/var/log/httpd"},
		{"/no/trailing/slash", "/no/trailing/slash"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := NormalizePath(tt.input)
			if result != tt.expected {
				t.Errorf("NormalizePath(%q) = %q, want %q",
					tt.input, result, tt.expected)
			}
		})
	}
}

func TestExtractBasePath(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"/var/www/*", "/var/www"},
		{"/etc/*.conf", "/etc"},
		{"/home/*/public_html", "/home"},
		{"/var/log/httpd/*.log", "/var/log/httpd"},
		{"/etc/httpd.conf", "/etc/httpd.conf"},
		{"/", "/"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := ExtractBasePath(tt.input)
			if result != tt.expected {
				t.Errorf("ExtractBasePath(%q) = %q, want %q",
					tt.input, result, tt.expected)
			}
		})
	}
}
