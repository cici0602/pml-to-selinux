package mapping

import (
	"testing"
)

// TestPathMapper_BraceExpansion tests brace expansion patterns
func TestPathMapper_BraceExpansion(t *testing.T) {
	mapper := NewPathMapper()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "simple brace expansion",
			input:    "/var/{log,tmp}/*",
			expected: "/var/(log|tmp)(/.*)?",
		},
		{
			name:     "multiple alternatives",
			input:    "/etc/{nginx,apache2,httpd}/*.conf",
			expected: "/etc/(nginx|apache2|httpd)/[^/]+\\.conf",
		},
		{
			name:     "nested paths with braces",
			input:    "/usr/{local,share}/bin/*",
			expected: "/usr/(local|share)/bin(/.*)?",
		},
		{
			name:     "brace with spaces",
			input:    "/var/{ log , tmp }/*",
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

// TestPathMapper_DoubleStarPattern tests /** recursive patterns
func TestPathMapper_DoubleStarPattern(t *testing.T) {
	mapper := NewPathMapper()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "simple double star",
			input:    "/usr/**/bin",
			expected: "/usr/.*/bin",
		},
		{
			name:     "double star at end",
			input:    "/var/www/**",
			expected: "/var/www(/.*)?",
		},
		{
			name:     "double star in middle",
			input:    "/home/**/public_html/*.html",
			expected: "/home/.*/public_html/[^/]+\\.html",
		},
		{
			name:     "multiple double stars",
			input:    "/usr/**/share/**/doc",
			expected: "/usr/.*/share/.*/doc",
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

// TestPathMapper_CharacterClasses tests character class preservation
func TestPathMapper_CharacterClasses(t *testing.T) {
	mapper := NewPathMapper()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "alphabetic range",
			input:    "/etc/[a-z]*.conf",
			expected: "/etc/[a-z][^/]*\\.conf",
		},
		{
			name:     "numeric range",
			input:    "/dev/tty[0-9]*",
			expected: "/dev/tty[0-9][^/]*",
		},
		{
			name:     "alphanumeric range",
			input:    "/var/log/app[a-zA-Z0-9]*.log",
			expected: "/var/log/app[a-zA-Z0-9][^/]*\\.log",
		},
		{
			name:     "character set",
			input:    "/tmp/file[abc].txt",
			expected: "/tmp/file[abc]\\.txt",
		},
		{
			name:     "negated character class",
			input:    "/path/[!.]*.txt",
			expected: "/path/[!.][^/]*\\.txt",
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

// TestPathMapper_ComplexCombinations tests combinations of advanced patterns
func TestPathMapper_ComplexCombinations(t *testing.T) {
	mapper := NewPathMapper()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "braces with character class",
			input:    "/var/{log,tmp}/[a-z]*.log",
			expected: "/var/(log|tmp)/[a-z][^/]*\\.log",
		},
		{
			name:     "double star with braces",
			input:    "/usr/**/{bin,sbin}/*",
			expected: "/usr/.*/(bin|sbin)(/.*)?",
		},
		{
			name:     "all advanced features",
			input:    "/home/**/public_{html,www}/[a-z0-9]*.{php,html}",
			expected: "/home/.*/public_(html|www)/[a-z0-9][^/]*\\.(php|html)",
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

// TestPathMapper_EdgeCasesAdvanced tests edge cases for advanced patterns
func TestPathMapper_EdgeCasesAdvanced(t *testing.T) {
	mapper := NewPathMapper()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "empty braces",
			input:    "/var/{}/*",
			expected: "/var/()(/.*)?",
		},
		{
			name:     "single alternative",
			input:    "/var/{log}/*",
			expected: "/var/(log)(/.*)?",
		},
		{
			name:     "double star at start",
			input:    "/**/bin",
			expected: "/.*/bin",
		},
		{
			name:     "escaped characters with double star",
			input:    "/var/**/file.log",
			expected: "/var/.*/file\\.log",
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

// TestExpandBraces tests the expandBraces helper function
func TestExpandBraces(t *testing.T) {
	mapper := NewPathMapper()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "simple expansion",
			input:    "{a,b,c}",
			expected: "(a|b|c)",
		},
		{
			name:     "with spaces",
			input:    "{ a , b , c }",
			expected: "(a|b|c)",
		},
		{
			name:     "in path",
			input:    "/path/{one,two}/file",
			expected: "/path/(one|two)/file",
		},
		{
			name:     "no braces",
			input:    "/path/to/file",
			expected: "/path/to/file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mapper.expandBraces(tt.input)
			if result != tt.expected {
				t.Errorf("expandBraces(%q) = %q, want %q",
					tt.input, result, tt.expected)
			}
		})
	}
}

// TestHandleDoubleStarPattern tests the handleDoubleStarPattern helper function
func TestHandleDoubleStarPattern(t *testing.T) {
	mapper := NewPathMapper()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "middle double star",
			input:    "/usr/**/bin",
			expected: "/usr/.*/bin",
		},
		{
			name:     "ending double star",
			input:    "/var/www/**",
			expected: "/var/www(/.*)?",
		},
		{
			name:     "with wildcard before",
			input:    "/home/*/docs/**",
			expected: "/home/[^/]+/docs(/.*)?",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mapper.handleDoubleStarPattern(tt.input)
			if result != tt.expected {
				t.Errorf("handleDoubleStarPattern(%q) = %q, want %q",
					tt.input, result, tt.expected)
			}
		})
	}
}
