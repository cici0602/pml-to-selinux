package mapping

import (
	"testing"
)

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
			expected:     "httpd_var_logs_t",
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

// TestTypeMapper_TypeAttributes tests attribute inference
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
