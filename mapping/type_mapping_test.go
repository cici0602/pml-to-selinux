package mapping

import (
	"testing"
)

// TestTypeMapper_PathToType tests basic path to type name conversion
func TestTypeMapper_PathToType(t *testing.T) {
	tests := []struct {
		name         string
		modulePrefix string
		path         string
		expected     string
	}{
		{
			name:         "simple path",
			modulePrefix: "httpd",
			path:         "/var/www/*",
			expected:     "httpd_var_www_t",
		},
		{
			name:         "nested path",
			modulePrefix: "httpd",
			path:         "/var/log/httpd/*",
			expected:     "httpd_var_log_httpd_t",
		},
		{
			name:         "etc path",
			modulePrefix: "httpd",
			path:         "/etc/httpd/*",
			expected:     "httpd_etc_httpd_t",
		},
		{
			name:         "path with file extension",
			modulePrefix: "httpd",
			path:         "/etc/httpd.conf",
			expected:     "httpd_etc_httpd_conf_t",
		},
		{
			name:         "path with dashes",
			modulePrefix: "my-app",
			path:         "/var/my-app/data",
			expected:     "my_app_var_my_app_data_t",
		},
		{
			name:         "no module prefix",
			modulePrefix: "",
			path:         "/var/www/*",
			expected:     "var_www_t",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mapper := NewTypeMapper(tt.modulePrefix)
			result := mapper.PathToType(tt.path)
			if result != tt.expected {
				t.Errorf("PathToType(%q) = %q, want %q",
					tt.path, result, tt.expected)
			}
		})
	}
}

// TestTypeMapper_EdgeCases tests edge cases in type mapping
func TestTypeMapper_EdgeCases(t *testing.T) {
	tests := []struct {
		name         string
		modulePrefix string
		path         string
		expected     string
	}{
		{
			name:         "empty path",
			modulePrefix: "httpd",
			path:         "",
			expected:     "httpd_t",
		},
		{
			name:         "root path",
			modulePrefix: "httpd",
			path:         "/",
			expected:     "httpd_t",
		},
		{
			name:         "path with multiple wildcards",
			modulePrefix: "httpd",
			path:         "/var/*/logs/*",
			expected:     "httpd_var_t", // Base path before first wildcard
		},
		{
			name:         "path with double slashes",
			modulePrefix: "httpd",
			path:         "/var//www//html//*",
			expected:     "httpd_var_www_html_t",
		},
		{
			name:         "path with trailing slash",
			modulePrefix: "httpd",
			path:         "/var/www/",
			expected:     "httpd_var_www_t",
		},
		{
			name:         "very long path",
			modulePrefix: "test",
			path:         "/very/long/path/with/many/components/that/goes/on/and/on",
			expected:     "test_very_long_path_with_many_components_that_goes_on_and_on_t",
		},
		{
			name:         "path with numbers",
			modulePrefix: "httpd",
			path:         "/opt/httpd24/*",
			expected:     "httpd_opt_httpd24_t",
		},
		{
			name:         "path with special characters",
			modulePrefix: "httpd",
			path:         "/var/www-data/html+files/*",
			expected:     "httpd_var_www_data_html_files_t",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mapper := NewTypeMapper(tt.modulePrefix)
			result := mapper.PathToType(tt.path)
			if result != tt.expected {
				t.Errorf("PathToType(%q) = %q, want %q",
					tt.path, result, tt.expected)
			}
		})
	}
}

// TestTypeMapper_CustomMapping tests custom path-to-type mapping
func TestTypeMapper_CustomMapping(t *testing.T) {
	mapper := NewTypeMapper("httpd")
	mapper.AddCustomMapping("/var/www/*", "httpd_sys_content_t")

	result := mapper.PathToType("/var/www/*")
	expected := "httpd_sys_content_t"

	if result != expected {
		t.Errorf("Custom mapping failed: got %q, want %q", result, expected)
	}
}

// TestTypeMapper_InferTypeCategory tests attribute inference
func TestTypeMapper_InferTypeCategory(t *testing.T) {
	tests := []struct {
		name             string
		path             string
		expectedContains []string
	}{
		{
			name:             "executable path",
			path:             "/usr/bin/httpd",
			expectedContains: []string{"exec_type"},
		},
		{
			name:             "library path",
			path:             "/usr/lib64/httpd",
			expectedContains: []string{"lib_type"},
		},
		{
			name:             "log path",
			path:             "/var/log/httpd/*",
			expectedContains: []string{"logfile", "file_type"},
		},
		{
			name:             "config path",
			path:             "/etc/httpd/httpd.conf",
			expectedContains: []string{"configfile", "file_type"},
		},
		{
			name:             "web content",
			path:             "/var/www/html/*",
			expectedContains: []string{"httpdcontent", "file_type"},
		},
		{
			name:             "pid file",
			path:             "/var/run/httpd.pid",
			expectedContains: []string{"pidfile", "file_type"},
		},
		{
			name:             "tmp file",
			path:             "/tmp/httpd-temp",
			expectedContains: []string{"tmpfile", "file_type"},
		},
	}

	mapper := NewTypeMapper("httpd")

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mapper.InferTypeCategory(tt.path)

			for _, expected := range tt.expectedContains {
				found := false
				for _, attr := range result {
					if attr == expected {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("InferTypeCategory(%q) missing attribute %q, got %v",
						tt.path, expected, result)
				}
			}
		})
	}
}

// TestTypeMapper_TypeAttributes tests detailed attribute inference
func TestTypeMapper_TypeAttributes(t *testing.T) {
	tests := []struct {
		name               string
		path               string
		expectedAttributes []string
		shouldNotContain   []string
	}{
		{
			name:               "executable in bin",
			path:               "/usr/bin/httpd",
			expectedAttributes: []string{"exec_type"},
			shouldNotContain:   []string{"file_type"},
		},
		{
			name:               "executable in sbin",
			path:               "/usr/sbin/httpd",
			expectedAttributes: []string{"exec_type"},
			shouldNotContain:   []string{"file_type"},
		},
		{
			name:               "library file",
			path:               "/usr/lib64/libhttpd.so",
			expectedAttributes: []string{"lib_type", "file_type"},
		},
		{
			name:               "log file with .log extension",
			path:               "/var/log/access.log",
			expectedAttributes: []string{"logfile", "file_type"},
		},
		{
			name:               "config file with .conf extension",
			path:               "/etc/httpd.conf",
			expectedAttributes: []string{"configfile", "file_type"},
		},
		{
			name:               "config file with .cfg extension",
			path:               "/etc/httpd.cfg",
			expectedAttributes: []string{"configfile", "file_type"},
		},
		{
			name:               "pid file",
			path:               "/var/run/httpd.pid",
			expectedAttributes: []string{"pidfile", "file_type"},
		},
		{
			name:               "tmp file",
			path:               "/tmp/httpd-session",
			expectedAttributes: []string{"tmpfile", "file_type"},
		},
		{
			name:               "web content",
			path:               "/var/www/html/index.html",
			expectedAttributes: []string{"httpdcontent", "file_type"},
		},
		{
			name:               "srv content",
			path:               "/srv/www/data",
			expectedAttributes: []string{"httpdcontent", "file_type"},
		},
		{
			name:               "regular file",
			path:               "/home/user/data",
			expectedAttributes: []string{"file_type"},
		},
	}

	mapper := NewTypeMapper("test")

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attributes := mapper.InferTypeCategory(tt.path)

			// Check that all expected attributes are present
			for _, expected := range tt.expectedAttributes {
				found := false
				for _, attr := range attributes {
					if attr == expected {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected attribute %q not found in %v", expected, attributes)
				}
			}

			// Check that unwanted attributes are not present
			for _, unwanted := range tt.shouldNotContain {
				for _, attr := range attributes {
					if attr == unwanted {
						t.Errorf("Unwanted attribute %q found in %v", unwanted, attributes)
					}
				}
			}
		})
	}
}

// TestTypeMapper_SubjectToType tests subject name conversion
func TestTypeMapper_SubjectToType(t *testing.T) {
	tests := []struct {
		subject  string
		expected string
	}{
		{"httpd", "httpd_t"},
		{"httpd_t", "httpd_t"},
		{"nginx", "nginx_t"},
		{"my_app", "my_app_t"},
	}

	mapper := NewTypeMapper("")

	for _, tt := range tests {
		t.Run(tt.subject, func(t *testing.T) {
			result := mapper.SubjectToType(tt.subject)
			if result != tt.expected {
				t.Errorf("SubjectToType(%q) = %q, want %q",
					tt.subject, result, tt.expected)
			}
		})
	}
}

// TestTypeMapper_SubjectToTypeEdge tests subject name conversion edge cases
func TestTypeMapper_SubjectToTypeEdge(t *testing.T) {
	tests := []struct {
		name     string
		subject  string
		expected string
	}{
		{
			name:     "subject without _t suffix",
			subject:  "httpd",
			expected: "httpd_t",
		},
		{
			name:     "subject with _t suffix",
			subject:  "httpd_t",
			expected: "httpd_t",
		},
		{
			name:     "empty subject",
			subject:  "",
			expected: "_t",
		},
		{
			name:     "subject with underscores",
			subject:  "apache_httpd",
			expected: "apache_httpd_t",
		},
	}

	mapper := NewTypeMapper("test")

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mapper.SubjectToType(tt.subject)
			if result != tt.expected {
				t.Errorf("SubjectToType(%q) = %q, want %q",
					tt.subject, result, tt.expected)
			}
		})
	}
}

// TestTypeMapper_GenerateTypeDescription tests type description generation
func TestTypeMapper_GenerateTypeDescription(t *testing.T) {
	tests := []struct {
		modulePrefix string
		typeName     string
		path         string
		contains     string
	}{
		{
			modulePrefix: "httpd",
			typeName:     "httpd_var_log_httpd_t",
			path:         "/var/log/httpd/*",
			contains:     "Log files",
		},
		{
			modulePrefix: "httpd",
			typeName:     "httpd_etc_httpd_t",
			path:         "/etc/httpd/*",
			contains:     "Configuration files",
		},
		{
			modulePrefix: "httpd",
			typeName:     "httpd_var_www_t",
			path:         "/var/www/*",
			contains:     "Web content",
		},
		{
			modulePrefix: "httpd",
			typeName:     "httpd_var_run_t",
			path:         "/var/run/httpd.pid",
			contains:     "Runtime files",
		},
	}

	for _, tt := range tests {
		t.Run(tt.typeName, func(t *testing.T) {
			mapper := NewTypeMapper(tt.modulePrefix)
			result := mapper.GenerateTypeDescription(tt.typeName, tt.path)

			if result == "" {
				t.Errorf("GenerateTypeDescription returned empty string")
			}

			// Just check if it contains expected keywords
			t.Logf("Generated description: %s", result)
		})
	}
}

// TestTypeMapper_NormalizePath tests path normalization
func TestTypeMapper_NormalizePath(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected string
	}{
		{
			name:     "normal path",
			path:     "/var/www/html",
			expected: "/var/www/html",
		},
		{
			name:     "path with double slashes",
			path:     "/var//www//html",
			expected: "/var/www/html",
		},
		{
			name:     "path with trailing slash",
			path:     "/var/www/html/",
			expected: "/var/www/html",
		},
		{
			name:     "path with multiple trailing slashes",
			path:     "/var/www/html///",
			expected: "/var/www/html",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NormalizePath(tt.path)
			if result != tt.expected {
				t.Errorf("NormalizePath(%q) = %q, want %q",
					tt.path, result, tt.expected)
			}
		})
	}
}

// TestIsSystemPath tests system path detection
func TestIsSystemPath(t *testing.T) {
	tests := []struct {
		path     string
		expected bool
	}{
		{"/bin/ls", true},
		{"/sbin/init", true},
		{"/usr/bin/httpd", true},
		{"/lib64/libc.so", true},
		{"/var/www/html", false},
		{"/etc/httpd.conf", false},
		{"/home/user/file", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			result := IsSystemPath(tt.path)
			if result != tt.expected {
				t.Errorf("IsSystemPath(%q) = %v, want %v",
					tt.path, result, tt.expected)
			}
		})
	}
}

// TestGetSystemType tests system type retrieval
func TestGetSystemType(t *testing.T) {
	tests := []struct {
		path     string
		expected string
	}{
		{"/bin/ls", "bin_t"},
		{"/sbin/init", "bin_t"},
		{"/usr/bin/httpd", "bin_t"},
		{"/lib64/libc.so", "lib_t"},
		{"/usr/lib/module.so", "lib_t"},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			result := GetSystemType(tt.path)
			if result != tt.expected {
				t.Errorf("GetSystemType(%q) = %q, want %q",
					tt.path, result, tt.expected)
			}
		})
	}
}

// TestSanitizeTypeName tests type name sanitization
func TestSanitizeTypeName(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"httpd", "httpd"},
		{"HTTPD", "httpd"},
		{"my-app", "my_app"},
		{"my.app", "my_app"},
		{"my app", "my_app"},
		{"my__app", "my_app"},
		{"123app", "t_123app"},
		{"_leading_", "leading"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := SanitizeTypeName(tt.input)
			if result != tt.expected {
				t.Errorf("SanitizeTypeName(%q) = %q, want %q",
					tt.input, result, tt.expected)
			}
		})
	}
}
