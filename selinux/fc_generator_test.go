package selinux

import (
	"strings"
	"testing"

	"github.com/cici0602/pml-to-selinux/models"
)

// TestFCGenerator_Generate tests the complete FC file generation
func TestFCGenerator_Generate(t *testing.T) {
	policy := &models.SELinuxPolicy{
		ModuleName: "httpd",
		Version:    "1.0.0",
		FileContexts: []models.FileContext{
			{
				PathPattern: "/var/www/html(/.*)?",
				User:        "system_u",
				Role:        "object_r",
				FileType:    "httpd_sys_content_t",
				Level:       "s0",
			},
			{
				PathPattern: "/etc/httpd/conf/httpd\\.conf",
				User:        "system_u",
				Role:        "object_r",
				FileType:    "httpd_config_t",
				Level:       "s0",
			},
			{
				PathPattern: "/usr/sbin/httpd",
				User:        "system_u",
				Role:        "object_r",
				FileType:    "httpd_exec_t",
				Level:       "s0",
			},
		},
	}

	generator := NewFCGenerator(policy)
	result, err := generator.Generate()

	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	// Check header
	if !strings.Contains(result, "# SELinux File Contexts: httpd") {
		t.Error("Missing module name in header")
	}
	if !strings.Contains(result, "# Version: 1.0.0") {
		t.Error("Missing version in header")
	}

	// Check file contexts
	expectedContexts := []string{
		"/etc/httpd/conf/httpd\\.conf",
		"/usr/sbin/httpd",
		"/var/www/html(/.*)?",
	}

	for _, expected := range expectedContexts {
		if !strings.Contains(result, expected) {
			t.Errorf("Missing context for %s in output", expected)
		}
	}

	// Check gen_context format
	if !strings.Contains(result, "gen_context(system_u:object_r:httpd_sys_content_t:s0)") {
		t.Error("Missing or malformed gen_context for httpd_sys_content_t")
	}
}

// TestFCGenerator_EmptyPolicy tests generation with empty policy
func TestFCGenerator_EmptyPolicy(t *testing.T) {
	policy := &models.SELinuxPolicy{
		ModuleName:   "empty",
		Version:      "1.0.0",
		FileContexts: []models.FileContext{},
	}

	generator := NewFCGenerator(policy)
	result, err := generator.Generate()

	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	// Should have header but no file contexts
	if !strings.Contains(result, "# SELinux File Contexts: empty") {
		t.Error("Missing header")
	}

	// Should not have any gen_context lines
	if strings.Contains(result, "gen_context") {
		t.Error("Should not contain gen_context for empty policy")
	}
}

// TestFCGenerator_GroupContextsByDirectory tests directory grouping
func TestFCGenerator_GroupContextsByDirectory(t *testing.T) {
	policy := &models.SELinuxPolicy{
		ModuleName: "test",
		Version:    "1.0.0",
		FileContexts: []models.FileContext{
			{
				PathPattern: "/var/www/html(/.*)?",
				FileType:    "httpd_sys_content_t",
				User:        "system_u",
				Role:        "object_r",
				Level:       "s0",
			},
			{
				PathPattern: "/var/www/cgi-bin(/.*)?",
				FileType:    "httpd_sys_script_exec_t",
				User:        "system_u",
				Role:        "object_r",
				Level:       "s0",
			},
			{
				PathPattern: "/etc/httpd/conf/httpd\\.conf",
				FileType:    "httpd_config_t",
				User:        "system_u",
				Role:        "object_r",
				Level:       "s0",
			},
			{
				PathPattern: "/etc/httpd/logs(/.*)?",
				FileType:    "httpd_log_t",
				User:        "system_u",
				Role:        "object_r",
				Level:       "s0",
			},
		},
	}

	generator := NewFCGenerator(policy)
	result, err := generator.Generate()

	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	// Check that contexts are grouped by directory with comments
	if !strings.Contains(result, "# Contexts for /etc/httpd") {
		t.Error("Missing directory comment for /etc/httpd")
	}
	if !strings.Contains(result, "# Contexts for /var/www") {
		t.Error("Missing directory comment for /var/www")
	}

	// Check that /var/www contexts appear together
	varWwwIdx := strings.Index(result, "/var/www/html")
	varWwwCgiIdx := strings.Index(result, "/var/www/cgi-bin")
	etcHttpdIdx := strings.Index(result, "/etc/httpd/conf")

	if varWwwIdx == -1 || varWwwCgiIdx == -1 || etcHttpdIdx == -1 {
		t.Fatal("Missing expected contexts in output")
	}

	// /var/www contexts should be closer to each other than to /etc/httpd
	varWwwDist := abs(varWwwIdx - varWwwCgiIdx)
	etcDist := abs(varWwwIdx - etcHttpdIdx)

	if varWwwDist >= etcDist {
		t.Error("Contexts not properly grouped by directory")
	}
}

// TestFCGenerator_FileTypeSpecifiers tests file type specifiers
func TestFCGenerator_FileTypeSpecifiers(t *testing.T) {
	tests := []struct {
		name        string
		fileType    string
		pathPattern string
	}{
		{
			name:        "executable file",
			fileType:    "httpd_exec_t",
			pathPattern: "/usr/sbin/httpd",
		},
		{
			name:        "directory pattern",
			fileType:    "httpd_sys_content_t",
			pathPattern: "/var/www/html(/.*)?",
		},
		{
			name:        "config file",
			fileType:    "httpd_config_t",
			pathPattern: "/etc/httpd/conf/httpd\\.conf",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := &models.SELinuxPolicy{
				ModuleName: "test",
				Version:    "1.0.0",
				FileContexts: []models.FileContext{
					{
						PathPattern: tt.pathPattern,
						FileType:    tt.fileType,
						User:        "system_u",
						Role:        "object_r",
						Level:       "s0",
					},
				},
			}

			generator := NewFCGenerator(policy)
			result, err := generator.Generate()

			if err != nil {
				t.Fatalf("Generate() error = %v", err)
			}

			// Check that path pattern and file type appear in output
			if !strings.Contains(result, tt.pathPattern) {
				t.Errorf("Output should contain path pattern %q", tt.pathPattern)
			}
			if !strings.Contains(result, tt.fileType) {
				t.Errorf("Output should contain file type %q", tt.fileType)
			}
			// Check gen_context format
			if !strings.Contains(result, "gen_context(") {
				t.Error("Output should contain gen_context()")
			}
		})
	}
}

// TestFCGenerator_SortedOutput tests that output is sorted
func TestFCGenerator_SortedOutput(t *testing.T) {
	policy := &models.SELinuxPolicy{
		ModuleName: "test",
		Version:    "1.0.0",
		FileContexts: []models.FileContext{
			{
				PathPattern: "/var/www/html(/.*)?",
				FileType:    "httpd_sys_content_t",
				User:        "system_u",
				Role:        "object_r",
				Level:       "s0",
			},
			{
				PathPattern: "/etc/httpd/conf/httpd\\.conf",
				FileType:    "httpd_config_t",
				User:        "system_u",
				Role:        "object_r",
				Level:       "s0",
			},
			{
				PathPattern: "/usr/sbin/httpd",
				FileType:    "httpd_exec_t",
				User:        "system_u",
				Role:        "object_r",
				Level:       "s0",
			},
		},
	}

	generator := NewFCGenerator(policy)
	result, err := generator.Generate()

	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	// Check order: /etc should come before /usr, which should come before /var
	etcIdx := strings.Index(result, "/etc/httpd")
	usrIdx := strings.Index(result, "/usr/sbin")
	varIdx := strings.Index(result, "/var/www")

	if etcIdx == -1 || usrIdx == -1 || varIdx == -1 {
		t.Fatal("Missing expected paths in output")
	}

	if !(etcIdx < usrIdx && usrIdx < varIdx) {
		t.Error("File contexts not sorted correctly")
	}
}

// TestFCGenerator_ComplexPatterns tests complex path patterns
func TestFCGenerator_ComplexPatterns(t *testing.T) {
	policy := &models.SELinuxPolicy{
		ModuleName: "complex",
		Version:    "1.0.0",
		FileContexts: []models.FileContext{
			{
				PathPattern: "/var/www/[^/]+/public_html(/.*)?",
				FileType:    "httpd_user_content_t",
				User:        "system_u",
				Role:        "object_r",
				Level:       "s0",
			},
			{
				PathPattern: "/etc/(apache2|httpd)/.*\\.conf",
				FileType:    "httpd_config_t",
				User:        "system_u",
				Role:        "object_r",
				Level:       "s0",
			},
			{
				PathPattern: "/opt/app-[0-9]+/bin(/.*)?",
				FileType:    "app_exec_t",
				User:        "system_u",
				Role:        "object_r",
				Level:       "s0",
			},
		},
	}

	generator := NewFCGenerator(policy)
	result, err := generator.Generate()

	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	// Verify that complex patterns are preserved
	expectedPatterns := []string{
		"/var/www/[^/]+/public_html(/.*)?",
		"/etc/(apache2|httpd)/.*\\.conf",
		"/opt/app-[0-9]+/bin(/.*)?",
	}

	for _, pattern := range expectedPatterns {
		if !strings.Contains(result, pattern) {
			t.Errorf("Missing complex pattern: %s", pattern)
		}
	}
}

// TestExtractBaseDirectory tests base directory extraction
func TestExtractBaseDirectory(t *testing.T) {
	tests := []struct {
		name     string
		pattern  string
		expected string
	}{
		{
			name:     "simple path",
			pattern:  "/var/www/html",
			expected: "/var/www",
		},
		{
			name:     "recursive pattern",
			pattern:  "/var/www/html(/.*)?",
			expected: "/var/www",
		},
		{
			name:     "root file",
			pattern:  "/test.txt",
			expected: "/",
		},
		{
			name:     "deep path",
			pattern:  "/var/log/httpd/access.log",
			expected: "/var/log/httpd",
		},
		{
			name:     "pattern with regex",
			pattern:  "/etc/httpd/.*\\.conf",
			expected: "/etc/httpd",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractBaseDirectory(tt.pattern)
			if result != tt.expected {
				t.Errorf("extractBaseDirectory(%q) = %q, want %q",
					tt.pattern, result, tt.expected)
			}
		})
	}
}

// TestGenerateFC tests the convenience function
func TestGenerateFC(t *testing.T) {
	policy := &models.SELinuxPolicy{
		ModuleName: "test",
		Version:    "1.0.0",
		FileContexts: []models.FileContext{
			{
				PathPattern: "/test/path",
				FileType:    "test_t",
				User:        "system_u",
				Role:        "object_r",
				Level:       "s0",
			},
		},
	}

	result, err := GenerateFC(policy)

	if err != nil {
		t.Fatalf("GenerateFC() error = %v", err)
	}

	if !strings.Contains(result, "/test/path") {
		t.Error("GenerateFC() should contain test path")
	}
}

// Helper function
func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}
