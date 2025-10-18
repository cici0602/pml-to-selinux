package mapping

import (
	"strings"
	"testing"
)

// TestPathMapper_BasicConversion tests basic path pattern conversion
func TestPathMapper_BasicConversion(t *testing.T) {
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
			expectedPattern: "/etc/[^/]+\\.conf",
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
			expectedPattern: "/etc/httpd/conf/httpd\\.conf",
		},
		{
			name:            "multiple wildcards",
			casbinPath:      "/var/*/logs/*.log",
			expectedPattern: "/var/[^/]+/logs/[^/]+\\.log",
		},
		{
			name:            "question mark wildcard",
			casbinPath:      "/var/log/httpd?.log",
			expectedPattern: "/var/log/httpd.\\.log",
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

// TestPathMapper_AdvancedPatterns tests advanced pattern features
func TestPathMapper_AdvancedPatterns(t *testing.T) {
	mapper := NewPathMapper()

	t.Run("brace expansion", func(t *testing.T) {
		tests := []struct {
			input    string
			expected string
		}{
			{"/var/{log,tmp}/*", "/var/(log|tmp)(/.*)?"},
			{"/etc/{nginx,apache2,httpd}/*.conf", "/etc/(nginx|apache2|httpd)/[^/]+\\.conf"},
			{"/usr/{local,share}/bin/*", "/usr/(local|share)/bin(/.*)?"},
		}

		for _, tt := range tests {
			result := mapper.ConvertToSELinuxPattern(tt.input)
			if result != tt.expected {
				t.Errorf("Brace expansion failed: %q -> %q, want %q", tt.input, result, tt.expected)
			}
		}
	})

	t.Run("double star pattern", func(t *testing.T) {
		tests := []struct {
			input    string
			expected string
		}{
			{"/usr/**/bin", "/usr/.*/bin"},
			{"/var/www/**", "/var/www(/.*)?"},
			{"/home/**/public_html/*.html", "/home/.*/public_html/[^/]+\\.html"},
		}

		for _, tt := range tests {
			result := mapper.ConvertToSELinuxPattern(tt.input)
			if result != tt.expected {
				t.Errorf("Double star pattern failed: %q -> %q, want %q", tt.input, result, tt.expected)
			}
		}
	})

	t.Run("character classes", func(t *testing.T) {
		tests := []struct {
			input    string
			expected string
		}{
			{"/etc/[a-z]*.conf", "/etc/[a-z][^/]*\\.conf"},
			{"/var/log/httpd[0-9].log", "/var/log/httpd[0-9]\\.log"},
		}

		for _, tt := range tests {
			result := mapper.ConvertToSELinuxPattern(tt.input)
			if result != tt.expected {
				t.Errorf("Character class failed: %q -> %q, want %q", tt.input, result, tt.expected)
			}
		}
	})
}

// TestPathMapper_FileTypeInference tests file type detection
func TestPathMapper_FileTypeInference(t *testing.T) {
	mapper := NewPathMapper()

	tests := []struct {
		name     string
		path     string
		expected string
	}{
		// Basic types
		{"directory with slash", "/var/www/", "directory"},
		{"wildcard path", "/var/www/*", "all files"},
		{"config file", "/etc/httpd.conf", "regular file"},
		{"log file", "/var/log/httpd/access.log", "regular file"},

		// Device files
		{"block device sda", "/dev/sda", "block"},
		{"block device nvme", "/dev/nvme0n1", "block"},
		{"char device tty", "/dev/tty0", "char"},
		{"char device null", "/dev/null", "char"},
		{"char device random", "/dev/random", "char"},

		// Socket files
		{"socket in run", "/run/dbus/system_bus_socket", "socket"},
		{"socket with .sock", "/var/run/docker.sock", "socket"},

		// Systemd files
		{"systemd service", "/lib/systemd/system/httpd.service", "regular file"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mapper.InferFileType(tt.path)
			if result != tt.expected {
				t.Errorf("InferFileType(%q) = %q, want %q", tt.path, result, tt.expected)
			}
		})
	}
}

// TestPathMapper_ContextTypeInference tests SELinux type inference
func TestPathMapper_ContextTypeInference(t *testing.T) {
	mapper := NewPathMapper()

	tests := []struct {
		path     string
		expected string
	}{
		{"/bin/bash", "bin_t"},
		{"/sbin/init", "bin_t"},
		{"/lib64/libc.so.6", "lib_t"},
		{"/etc/httpd.conf", "etc_t"},
		{"/var/log/messages", "var_log_t"},
		{"/tmp/test.txt", "tmp_t"},
		{"/run/httpd.pid", "var_run_t"},
		{"/home/user/file", "user_home_t"},
		{"/dev/sda", "device_t"},
	}

	for _, tt := range tests {
		result := mapper.InferContextType(tt.path)
		if result != tt.expected {
			t.Errorf("InferContextType(%q) = %q, want %q", tt.path, result, tt.expected)
		}
	}
}

// TestPathMapper_RecursivePatterns tests recursive pattern generation
func TestPathMapper_RecursivePatterns(t *testing.T) {
	mapper := NewPathMapper()

	tests := []struct {
		name     string
		path     string
		expected []PathPattern
	}{
		{
			name: "simple recursive",
			path: "/var/www/*",
			expected: []PathPattern{
				{Pattern: "/var/www(/.*)?", FileType: "all files"},
			},
		},
		{
			name: "non-recursive file",
			path: "/etc/httpd.conf",
			expected: []PathPattern{
				{Pattern: "/etc/httpd\\.conf", FileType: "regular file"},
			},
		},
		{
			name: "non-recursive directory",
			path: "/var/www/",
			expected: []PathPattern{
				{Pattern: "/var/www/", FileType: "directory"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			patterns := mapper.GenerateRecursivePatterns(tt.path)
			if len(patterns) != len(tt.expected) {
				t.Fatalf("Expected %d patterns, got %d", len(tt.expected), len(patterns))
			}

			for i := range patterns {
				if patterns[i].Pattern != tt.expected[i].Pattern {
					t.Errorf("Pattern[%d]: got %q, want %q", i, patterns[i].Pattern, tt.expected[i].Pattern)
				}
				if patterns[i].FileType != tt.expected[i].FileType {
					t.Errorf("FileType[%d]: got %q, want %q", i, patterns[i].FileType, tt.expected[i].FileType)
				}
			}
		})
	}
}

// TestPathMapper_PatternMatching tests pattern matching functionality
func TestPathMapper_PatternMatching(t *testing.T) {
	mapper := NewPathMapper()

	tests := []struct {
		pattern     string
		testPath    string
		shouldMatch bool
	}{
		{"/etc/passwd", "/etc/passwd", true},
		{"/var/www(/.*)?", "/var/www/html/index.html", true},
		{"/var/www(/.*)?", "/var/www", true},
		{"/etc/[^/]+\\.conf", "/etc/httpd.conf", true},
		{"/etc/[^/]+\\.conf", "/etc/httpd.cfg", false},
		{"/etc/[^/]+\\.conf", "/etc/httpd/httpd.conf", false},
		{"/var/(log|tmp)(/.*)?", "/var/log/messages", true},
		{"/var/(log|tmp)(/.*)?", "/var/tmp/test", true},
		{"/var/(log|tmp)(/.*)?", "/var/cache/test", false},
	}

	for _, tt := range tests {
		matched, err := mapper.MatchPattern(tt.pattern, tt.testPath)
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
			continue
		}

		if matched != tt.shouldMatch {
			t.Errorf("MatchPattern(%q, %q) = %v, want %v",
				tt.pattern, tt.testPath, matched, tt.shouldMatch)
		}
	}
}

// TestPathMapper_UtilityFunctions tests utility functions
func TestPathMapper_UtilityFunctions(t *testing.T) {
	mapper := NewPathMapper()

	t.Run("SplitPathPattern", func(t *testing.T) {
		tests := []struct {
			path             string
			expectedBase     string
			expectedWildcard string
		}{
			{"/var/www/*.html", "/var/www", "*.html"},
			{"/etc/httpd/*", "/etc/httpd", "*"},
			{"/home/*/public", "/home", "*/public"},
			{"/etc/passwd", "/etc/passwd", ""},
		}

		for _, tt := range tests {
			base, wildcard := mapper.SplitPathPattern(tt.path)
			if base != tt.expectedBase || wildcard != tt.expectedWildcard {
				t.Errorf("SplitPathPattern(%q) = (%q, %q), want (%q, %q)",
					tt.path, base, wildcard, tt.expectedBase, tt.expectedWildcard)
			}
		}
	})

	t.Run("NormalizePath", func(t *testing.T) {
		tests := []struct {
			input    string
			expected string
		}{
			{"/var/www/", "/var/www"},
			{"/var//www", "/var/www"},
			{"/", "/"},
			{"//etc//passwd", "/etc/passwd"},
		}

		for _, tt := range tests {
			result := NormalizePath(tt.input)
			if result != tt.expected {
				t.Errorf("NormalizePath(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		}
	})

	t.Run("ExtractBasePath", func(t *testing.T) {
		tests := []struct {
			input    string
			expected string
		}{
			{"/var/www/*", "/var/www"},
			{"/etc/*.conf", "/etc"},
			{"/home/*/public_html", "/home"},
			{"/etc/httpd.conf", "/etc/httpd.conf"},
		}

		for _, tt := range tests {
			result := ExtractBasePath(tt.input)
			if result != tt.expected {
				t.Errorf("ExtractBasePath(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		}
	})
}

// TestPathMapper_CustomMappings tests custom mapping functionality
func TestPathMapper_CustomMappings(t *testing.T) {
	mapper := NewPathMapper()
	mapper.AddCustomMapping("/custom/path/*", "/custom/path(/.+)?")

	result := mapper.ConvertToSELinuxPattern("/custom/path/*")
	expected := "/custom/path(/.+)?"

	if result != expected {
		t.Errorf("Custom mapping failed: got %q, want %q", result, expected)
	}
}

// TestPathMapper_EdgeCases tests edge cases
func TestPathMapper_EdgeCases(t *testing.T) {
	mapper := NewPathMapper()

	tests := []struct {
		name     string
		path     string
		checkFn  func(string) bool
		errorMsg string
	}{
		{
			name: "empty path",
			path: "",
			checkFn: func(s string) bool {
				return s == ""
			},
			errorMsg: "Empty path should return empty pattern",
		},
		{
			name: "root path",
			path: "/",
			checkFn: func(s string) bool {
				return s == "/"
			},
			errorMsg: "Root path should be preserved",
		},
		{
			name: "path with multiple dots",
			path: "/etc/file.tar.gz",
			checkFn: func(s string) bool {
				return strings.Contains(s, "\\.")
			},
			errorMsg: "Dots should be escaped",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mapper.ConvertToSELinuxPattern(tt.path)
			if !tt.checkFn(result) {
				t.Error(tt.errorMsg + ": got " + result)
			}
		})
	}
}
