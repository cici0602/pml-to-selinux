package mapping

import (
	"testing"
)

// TestPathMapper_ConvertToSELinuxPattern tests basic pattern conversion
func TestPathMapper_ConvertToSELinuxPattern(t *testing.T) {
	mapper := NewPathMapper()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "simple recursive pattern",
			input:    "/var/www/*",
			expected: "/var/www(/.*)?",
		},
		{
			name:     "exact path",
			input:    "/etc/passwd",
			expected: "/etc/passwd",
		},
		{
			name:     "wildcard in filename",
			input:    "/etc/*.conf",
			expected: "/etc/[^/]+\\.conf",
		},
		{
			name:     "nested recursive",
			input:    "/var/log/httpd/*",
			expected: "/var/log/httpd(/.*)?",
		},
		{
			name:     "home directory wildcard",
			input:    "/home/*/public_html",
			expected: "/home/[^/]+/public_html",
		},
		{
			name:     "double star pattern",
			input:    "/usr/**/bin",
			expected: "/usr/.*/bin",
		},
		{
			name:     "brace expansion",
			input:    "/var/{log,tmp}/*",
			expected: "/var/(log|tmp)(/.*)?",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mapper.ConvertToSELinuxPattern(tt.input)
			if result != tt.expected {
				t.Errorf("ConvertToSELinuxPattern(%q) = %q, want %q",
					tt.input, result, tt.expected)
			}
		})
	}
}

// TestPathMapper_IsDirectoryPattern tests directory pattern detection
func TestPathMapper_IsDirectoryPattern(t *testing.T) {
	mapper := NewPathMapper()

	tests := []struct {
		path     string
		expected bool
	}{
		{"/var/www/", true},
		{"/var/www/*", true},
		{"/etc/", true},
		{"/etc/passwd", false},
		{"/var/log/messages", false},
		{"/bin", true},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			result := mapper.IsDirectoryPattern(tt.path)
			if result != tt.expected {
				t.Errorf("IsDirectoryPattern(%q) = %v, want %v",
					tt.path, result, tt.expected)
			}
		})
	}
}

// TestPathMapper_IsRecursivePattern tests recursive pattern detection
func TestPathMapper_IsRecursivePattern(t *testing.T) {
	mapper := NewPathMapper()

	tests := []struct {
		path     string
		expected bool
	}{
		{"/var/www/*", true},
		{"/etc/*.conf", false},
		{"/home/*/public", false},
		{"/var/log/httpd/*", true},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			result := mapper.IsRecursivePattern(tt.path)
			if result != tt.expected {
				t.Errorf("IsRecursivePattern(%q) = %v, want %v",
					tt.path, result, tt.expected)
			}
		})
	}
}

// TestPathMapper_DeviceFiles tests device file type inference
func TestPathMapper_DeviceFiles(t *testing.T) {
	mapper := NewPathMapper()

	tests := []struct {
		name         string
		path         string
		expectedType string
	}{
		{
			name:         "block device - sda",
			path:         "/dev/sda",
			expectedType: "block",
		},
		{
			name:         "block device - nvme",
			path:         "/dev/nvme0n1",
			expectedType: "block",
		},
		{
			name:         "character device - tty",
			path:         "/dev/tty0",
			expectedType: "char",
		},
		{
			name:         "character device - null",
			path:         "/dev/null",
			expectedType: "char",
		},
		{
			name:         "character device - random",
			path:         "/dev/random",
			expectedType: "char",
		},
		{
			name:         "loop device",
			path:         "/dev/loop0",
			expectedType: "block",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mapper.InferFileType(tt.path)
			if result != tt.expectedType {
				t.Errorf("InferFileType(%q) = %q, want %q", tt.path, result, tt.expectedType)
			}
		})
	}
}

// TestPathMapper_SocketFiles tests socket file type inference
func TestPathMapper_SocketFiles(t *testing.T) {
	mapper := NewPathMapper()

	tests := []struct {
		name         string
		path         string
		expectedType string
	}{
		{
			name:         "socket file in run",
			path:         "/run/dbus/system_bus_socket",
			expectedType: "socket",
		},
		{
			name:         "socket with .sock extension",
			path:         "/var/run/docker.sock",
			expectedType: "socket",
		},
		{
			name:         "systemd socket",
			path:         "/run/systemd/notify.socket",
			expectedType: "socket",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mapper.InferFileType(tt.path)
			if result != tt.expectedType {
				t.Errorf("InferFileType(%q) = %q, want %q", tt.path, result, tt.expectedType)
			}
		})
	}
}

// TestPathMapper_InferContextType tests context type inference
func TestPathMapper_InferContextType(t *testing.T) {
	mapper := NewPathMapper()

	tests := []struct {
		name     string
		path     string
		expected string
	}{
		{
			name:     "bin directory",
			path:     "/bin/bash",
			expected: "bin_t",
		},
		{
			name:     "sbin directory",
			path:     "/sbin/init",
			expected: "bin_t",
		},
		{
			name:     "library file",
			path:     "/lib64/libc.so.6",
			expected: "lib_t",
		},
		{
			name:     "config file",
			path:     "/etc/httpd.conf",
			expected: "etc_t",
		},
		{
			name:     "log file",
			path:     "/var/log/messages",
			expected: "var_log_t",
		},
		{
			name:     "tmp file",
			path:     "/tmp/test.txt",
			expected: "tmp_t",
		},
		{
			name:     "runtime file",
			path:     "/run/httpd.pid",
			expected: "var_run_t",
		},
		{
			name:     "home directory",
			path:     "/home/user/file",
			expected: "user_home_t",
		},
		{
			name:     "device file",
			path:     "/dev/sda",
			expected: "device_t",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mapper.InferContextType(tt.path)
			if result != tt.expected {
				t.Errorf("InferContextType(%q) = %q, want %q", tt.path, result, tt.expected)
			}
		})
	}
}

// TestPathMapper_SplitPathPattern tests path pattern splitting
func TestPathMapper_SplitPathPattern(t *testing.T) {
	mapper := NewPathMapper()

	tests := []struct {
		name             string
		path             string
		expectedBase     string
		expectedWildcard string
	}{
		{
			name:             "simple wildcard",
			path:             "/var/www/*.html",
			expectedBase:     "/var/www",
			expectedWildcard: "*.html",
		},
		{
			name:             "recursive wildcard",
			path:             "/etc/httpd/*",
			expectedBase:     "/etc/httpd",
			expectedWildcard: "*",
		},
		{
			name:             "middle wildcard",
			path:             "/home/*/public",
			expectedBase:     "/home",
			expectedWildcard: "*/public",
		},
		{
			name:             "no wildcard",
			path:             "/etc/passwd",
			expectedBase:     "/etc/passwd",
			expectedWildcard: "",
		},
		{
			name:             "brace expansion",
			path:             "/var/{log,tmp}/*",
			expectedBase:     "/var",
			expectedWildcard: "{log,tmp}/*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			base, wildcard := mapper.SplitPathPattern(tt.path)
			if base != tt.expectedBase {
				t.Errorf("SplitPathPattern(%q) base = %q, want %q", tt.path, base, tt.expectedBase)
			}
			if wildcard != tt.expectedWildcard {
				t.Errorf("SplitPathPattern(%q) wildcard = %q, want %q", tt.path, wildcard, tt.expectedWildcard)
			}
		})
	}
}

// TestPathMapper_MatchPattern tests pattern matching
func TestPathMapper_MatchPattern(t *testing.T) {
	mapper := NewPathMapper()

	tests := []struct {
		name        string
		pattern     string
		testPath    string
		shouldMatch bool
		shouldError bool
	}{
		{
			name:        "exact match",
			pattern:     "/etc/passwd",
			testPath:    "/etc/passwd",
			shouldMatch: true,
		},
		{
			name:        "recursive match",
			pattern:     "/var/www(/.*)?",
			testPath:    "/var/www/html/index.html",
			shouldMatch: true,
		},
		{
			name:        "recursive match - directory itself",
			pattern:     "/var/www(/.*)?",
			testPath:    "/var/www",
			shouldMatch: true,
		},
		{
			name:        "wildcard match",
			pattern:     "/etc/[^/]+\\.conf",
			testPath:    "/etc/httpd.conf",
			shouldMatch: true,
		},
		{
			name:        "no match - wrong extension",
			pattern:     "/etc/[^/]+\\.conf",
			testPath:    "/etc/httpd.cfg",
			shouldMatch: false,
		},
		{
			name:        "no match - subdirectory",
			pattern:     "/etc/[^/]+\\.conf",
			testPath:    "/etc/httpd/httpd.conf",
			shouldMatch: false,
		},
		{
			name:        "alternation match - first option",
			pattern:     "/var/(log|tmp)(/.*)?",
			testPath:    "/var/log/messages",
			shouldMatch: true,
		},
		{
			name:        "alternation match - second option",
			pattern:     "/var/(log|tmp)(/.*)?",
			testPath:    "/var/tmp/test",
			shouldMatch: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matched, err := mapper.MatchPattern(tt.pattern, tt.testPath)

			if tt.shouldError {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if matched != tt.shouldMatch {
				t.Errorf("MatchPattern(%q, %q) = %v, want %v", tt.pattern, tt.testPath, matched, tt.shouldMatch)
			}
		})
	}
}

// TestPathMapper_ComplexDevicePatterns tests complex device file patterns
func TestPathMapper_ComplexDevicePatterns(t *testing.T) {
	mapper := NewPathMapper()

	tests := []struct {
		name     string
		path     string
		expected string
	}{
		{
			name:     "all tty devices",
			path:     "/dev/tty*",
			expected: "/dev/tty[^/]+",
		},
		{
			name:     "all block devices",
			path:     "/dev/sd*",
			expected: "/dev/sd[^/]+",
		},
		{
			name:     "pts directory",
			path:     "/dev/pts/*",
			expected: "/dev/pts(/.*)?",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mapper.ConvertToSELinuxPattern(tt.path)
			if result != tt.expected {
				t.Errorf("ConvertToSELinuxPattern(%q) = %q, want %q", tt.path, result, tt.expected)
			}
		})
	}
}

// TestPathMapper_SystemdPaths tests systemd-related path patterns
func TestPathMapper_SystemdPaths(t *testing.T) {
	mapper := NewPathMapper()

	tests := []struct {
		name         string
		path         string
		expectedType string
	}{
		{
			name:         "systemd service file",
			path:         "/lib/systemd/system/httpd.service",
			expectedType: "regular file",
		},
		{
			name:         "systemd target file",
			path:         "/lib/systemd/system/multi-user.target",
			expectedType: "regular file",
		},
		{
			name:         "systemd socket file",
			path:         "/run/systemd/notify.socket",
			expectedType: "socket",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mapper.InferFileType(tt.path)
			if result != tt.expectedType {
				t.Errorf("InferFileType(%q) = %q, want %q", tt.path, result, tt.expectedType)
			}
		})
	}
}
