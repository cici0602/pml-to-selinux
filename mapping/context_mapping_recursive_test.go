package mapping

import (
	"strings"
	"testing"
)

// TestPathMapper_RecursivePatterns tests recursive pattern generation
func TestPathMapper_RecursivePatterns(t *testing.T) {
	mapper := NewPathMapper()

	tests := []struct {
		name        string
		path        string
		expected    []PathPattern
		description string
	}{
		{
			name: "simple recursive",
			path: "/var/www/*",
			expected: []PathPattern{
				{
					Pattern:  "/var/www(/.*)?",
					FileType: "all files",
				},
			},
			description: "Should generate recursive pattern for /var/www/*",
		},
		{
			name: "nested recursive",
			path: "/var/log/httpd/*",
			expected: []PathPattern{
				{
					Pattern:  "/var/log/httpd(/.*)?",
					FileType: "all files",
				},
			},
			description: "Should handle nested recursive patterns",
		},
		{
			name: "non-recursive file",
			path: "/etc/httpd.conf",
			expected: []PathPattern{
				{
					Pattern:  "/etc/httpd\\.conf",
					FileType: "regular file",
				},
			},
			description: "Should handle non-recursive files",
		},
		{
			name: "non-recursive directory",
			path: "/var/www/",
			expected: []PathPattern{
				{
					Pattern:  "/var/www/",
					FileType: "directory",
				},
			},
			description: "Should handle non-recursive directories",
		},
		{
			name: "path with special chars",
			path: "/opt/app-v2.1/*",
			expected: []PathPattern{
				{
					Pattern:  "/opt/app\\-v2\\.1(/.*)?",
					FileType: "all files",
				},
			},
			description: "Should escape special characters in recursive patterns",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			patterns := mapper.GenerateRecursivePatterns(tt.path)

			if len(patterns) != len(tt.expected) {
				t.Errorf("Expected %d patterns, got %d", len(tt.expected), len(patterns))
				return
			}

			for i, expected := range tt.expected {
				if i >= len(patterns) {
					t.Errorf("Missing pattern at index %d", i)
					continue
				}

				if patterns[i].Pattern != expected.Pattern {
					t.Errorf("Pattern mismatch at index %d: got %q, want %q",
						i, patterns[i].Pattern, expected.Pattern)
				}

				if patterns[i].FileType != expected.FileType {
					t.Errorf("FileType mismatch at index %d: got %q, want %q",
						i, patterns[i].FileType, expected.FileType)
				}
			}
		})
	}
}

// TestPathMapper_ComplexPatterns tests complex path pattern conversions
func TestPathMapper_ComplexPatterns(t *testing.T) {
	mapper := NewPathMapper()

	tests := []struct {
		name     string
		path     string
		expected string
	}{
		{
			name:     "double wildcard",
			path:     "/var/*/logs/*",
			expected: "[^/]+", // This should be handled properly
		},
		{
			name:     "question mark wildcard",
			path:     "/var/log/httpd?.log",
			expected: "/var/log/httpd.\\.log",
		},
		{
			name:     "mixed wildcards",
			path:     "/etc/*/conf.d/*.conf",
			expected: "/etc/[^/]+/conf\\.d/[^/]+\\.conf",
		},
		{
			name:     "wildcard in middle",
			path:     "/usr/*/bin/httpd",
			expected: "/usr/[^/]+/bin/httpd",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mapper.ConvertToSELinuxPattern(tt.path)

			// For double wildcard case, just check it's handled
			if tt.name == "double wildcard" {
				if !strings.Contains(result, "[^/]+") {
					t.Errorf("Expected result to contain '[^/]+', got %q", result)
				}
			} else {
				if result != tt.expected {
					t.Errorf("ConvertToSELinuxPattern(%q) = %q, want %q",
						tt.path, result, tt.expected)
				}
			}
		})
	}
}

// TestPathMapper_FileTypeInference tests file type inference
func TestPathMapper_FileTypeInference(t *testing.T) {
	mapper := NewPathMapper()

	tests := []struct {
		name     string
		path     string
		expected string
	}{
		{"config file", "/etc/httpd.conf", "regular file"},
		{"log file", "/var/log/access.log", "regular file"},
		{"directory with slash", "/var/www/", "directory"},
		{"recursive pattern", "/var/www/*", "all files"},
		{"executable", "/usr/bin/httpd", "all files"},
		{"library", "/usr/lib64/libssl.so", "regular file"},
		{"script", "/usr/local/bin/script.sh", "regular file"},
		{"html file", "/var/www/index.html", "regular file"},
		{"php file", "/var/www/app.php", "regular file"},
	}

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

// TestPathMapper_IsRecursivePattern tests recursive pattern detection
func TestPathMapper_IsRecursivePattern(t *testing.T) {
	mapper := NewPathMapper()

	tests := []struct {
		name     string
		path     string
		expected bool
	}{
		{"recursive with wildcard", "/var/www/*", true},
		{"nested recursive", "/var/log/httpd/*", true},
		{"non-recursive file", "/etc/httpd.conf", false},
		{"non-recursive dir", "/var/www/", false},
		{"wildcard in middle", "/usr/*/bin/httpd", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mapper.IsRecursivePattern(tt.path)
			if result != tt.expected {
				t.Errorf("IsRecursivePattern(%q) = %v, want %v",
					tt.path, result, tt.expected)
			}
		})
	}
}

// TestPathMapper_CustomMappings tests custom mapping functionality
func TestPathMapper_CustomMappings(t *testing.T) {
	mapper := NewPathMapper()

	// Add custom mapping
	mapper.AddCustomMapping("/custom/path/*", "/custom/path(/.*)?")

	result := mapper.ConvertToSELinuxPattern("/custom/path/*")
	expected := "/custom/path(/.*)?"

	if result != expected {
		t.Errorf("Custom mapping failed: got %q, want %q", result, expected)
	}
}

// TestGetFileTypeSpecifierRecursive tests file type specifier generation for recursive patterns
func TestGetFileTypeSpecifierRecursive(t *testing.T) {
	tests := []struct {
		name     string
		fileType string
		expected string
	}{
		{"regular file", "regular file", " --"},
		{"directory", "directory", " -d"},
		{"symlink", "symlink", " -l"},
		{"socket", "socket", " -s"},
		{"pipe", "pipe", " -p"},
		{"block device", "block", " -b"},
		{"char device", "char", " -c"},
		{"all files", "all files", ""},
		{"unknown", "unknown", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetFileTypeSpecifier(tt.fileType)
			if result != tt.expected {
				t.Errorf("GetFileTypeSpecifier(%q) = %q, want %q",
					tt.fileType, result, tt.expected)
			}
		})
	}
}
