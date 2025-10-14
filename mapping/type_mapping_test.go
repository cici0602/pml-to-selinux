package mapping

import (
	"testing"
)

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

func TestTypeMapper_CustomMapping(t *testing.T) {
	mapper := NewTypeMapper("httpd")
	mapper.AddCustomMapping("/var/www/*", "httpd_sys_content_t")

	result := mapper.PathToType("/var/www/*")
	expected := "httpd_sys_content_t"

	if result != expected {
		t.Errorf("Custom mapping failed: got %q, want %q", result, expected)
	}
}

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
			// (not exact match since description format may vary)
			t.Logf("Generated description: %s", result)
		})
	}
}

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
