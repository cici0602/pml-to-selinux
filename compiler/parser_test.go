package compiler

import (
	"os"
	"path/filepath"
	"testing"
)

// TestParseModel tests parsing of PML model files
func TestParseModel(t *testing.T) {
	tests := []struct {
		name        string
		modelData   string
		policyData  string
		wantErr     bool
		errContains string
		checkFunc   func(*testing.T, *Parser)
	}{
		{
			name: "valid basic model",
			modelData: `[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act, eft

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow)) && !some(where (p.eft == deny))

[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
`,
			policyData: `p, httpd_t, /var/www/*, read, allow`,
			wantErr:    false,
			checkFunc: func(t *testing.T, p *Parser) {
				pml, err := p.Parse()
				if err != nil {
					t.Fatalf("Parse() error = %v", err)
				}
				if pml.Model == nil {
					t.Fatal("Model is nil")
				}
				if len(pml.Model.RequestDefinition["r"]) != 3 {
					t.Errorf("Expected 3 request definition fields, got %d", len(pml.Model.RequestDefinition["r"]))
				}
				if pml.Model.Matchers == "" {
					t.Error("Matchers should not be empty")
				}
				if pml.Model.Effect == "" {
					t.Error("Effect should not be empty")
				}
			},
		},
		{
			name: "model with comments and empty lines",
			modelData: `# This is a comment
[request_definition]
# Another comment
r = sub, obj, act

# Empty lines should be ignored

[policy_definition]
p = sub, obj, act, eft

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == p.sub
`,
			policyData: `# Comment in policy
p, httpd_t, /var/www/*, read, allow
`,
			wantErr: false,
			checkFunc: func(t *testing.T, p *Parser) {
				pml, err := p.Parse()
				if err != nil {
					t.Fatalf("Parse() error = %v", err)
				}
				if len(pml.Policies) != 1 {
					t.Errorf("Expected 1 policy, got %d", len(pml.Policies))
				}
			},
		},
		{
			name: "invalid model - missing sections",
			modelData: `[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act, eft

[matchers]
m = r.sub == p.sub

[policy_effect]
e = some(where (p.eft == allow))
`,
			policyData: `p, httpd_t, /var/www/*, read, allow`,
			wantErr:    false, // Parser should succeed, analyzer will catch missing sections
			checkFunc:  nil,
		},
		{
			name: "content outside section",
			modelData: `r = sub, obj, act
[request_definition]
`,
			policyData:  `p, httpd_t, /var/www/*, read, allow`,
			wantErr:     true,
			errContains: "content found outside of section",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary files
			tmpDir := t.TempDir()
			modelPath := filepath.Join(tmpDir, "model.conf")
			policyPath := filepath.Join(tmpDir, "policy.csv")

			if err := os.WriteFile(modelPath, []byte(tt.modelData), 0644); err != nil {
				t.Fatalf("Failed to write model file: %v", err)
			}
			if err := os.WriteFile(policyPath, []byte(tt.policyData), 0644); err != nil {
				t.Fatalf("Failed to write policy file: %v", err)
			}

			parser := NewParser(modelPath, policyPath)
			_, err := parser.Parse()

			if (err != nil) != tt.wantErr {
				t.Errorf("Parse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.errContains != "" && err != nil {
				if !contains(err.Error(), tt.errContains) {
					t.Errorf("Parse() error = %v, should contain %q", err, tt.errContains)
				}
			}

			if tt.checkFunc != nil {
				tt.checkFunc(t, parser)
			}
		})
	}
}

// TestParsePolicy tests parsing of CSV policy files
func TestParsePolicy(t *testing.T) {
	tests := []struct {
		name          string
		policyData    string
		wantPolicies  int
		wantRoles     int
		wantErr       bool
		checkPolicies func(*testing.T, *Parser)
	}{
		{
			name: "valid policies with allow and deny",
			policyData: `p, httpd_t, /var/www/*, read, allow
p, httpd_t, /var/www/*, write, allow
p, httpd_t, /usr/bin/*, write, deny
`,
			wantPolicies: 3,
			wantRoles:    0,
			wantErr:      false,
			checkPolicies: func(t *testing.T, p *Parser) {
				pml, _ := p.Parse()
				if pml.Policies[0].Subject != "httpd_t" {
					t.Errorf("Expected subject 'httpd_t', got %q", pml.Policies[0].Subject)
				}
				if pml.Policies[0].Effect != "allow" {
					t.Errorf("Expected effect 'allow', got %q", pml.Policies[0].Effect)
				}
				if pml.Policies[2].Effect != "deny" {
					t.Errorf("Expected effect 'deny', got %q", pml.Policies[2].Effect)
				}
			},
		},
		{
			name: "policies with role relations",
			policyData: `p, httpd_t, /var/www/*, read, allow
g, user_u, user_r
g2, httpd_t, web_domain
`,
			wantPolicies: 1,
			wantRoles:    2,
			wantErr:      false,
			checkPolicies: func(t *testing.T, p *Parser) {
				pml, _ := p.Parse()
				if len(pml.Roles) != 2 {
					t.Errorf("Expected 2 roles, got %d", len(pml.Roles))
				}
			},
		},
		{
			name: "invalid policy - wrong field count",
			policyData: `p, httpd_t, /var/www/*, read
`,
			wantErr:      true,
			wantPolicies: 0,
		},
		{
			name: "invalid role - wrong field count",
			policyData: `g, user_u
`,
			wantErr: true,
		},
		{
			name: "with comments and empty lines",
			policyData: `# This is a comment
p, httpd_t, /var/www/*, read, allow

# Another comment
p, httpd_t, /var/log/*, write, allow
`,
			wantPolicies: 2,
			wantErr:      false,
		},
	}

	// Create a valid model for all tests
	modelData := `[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act, eft

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == p.sub
`

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			modelPath := filepath.Join(tmpDir, "model.conf")
			policyPath := filepath.Join(tmpDir, "policy.csv")

			if err := os.WriteFile(modelPath, []byte(modelData), 0644); err != nil {
				t.Fatalf("Failed to write model file: %v", err)
			}
			if err := os.WriteFile(policyPath, []byte(tt.policyData), 0644); err != nil {
				t.Fatalf("Failed to write policy file: %v", err)
			}

			parser := NewParser(modelPath, policyPath)
			pml, err := parser.Parse()

			if (err != nil) != tt.wantErr {
				t.Errorf("Parse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if len(pml.Policies) != tt.wantPolicies {
					t.Errorf("Expected %d policies, got %d", tt.wantPolicies, len(pml.Policies))
				}
				if tt.wantRoles > 0 && len(pml.Roles) != tt.wantRoles {
					t.Errorf("Expected %d roles, got %d", tt.wantRoles, len(pml.Roles))
				}
			}

			if tt.checkPolicies != nil {
				tt.checkPolicies(t, parser)
			}
		})
	}
}

// TestParseCSVLine tests the CSV line parsing function
func TestParseCSVLine(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		expected []string
	}{
		{
			name:     "simple CSV",
			line:     "p, httpd_t, /var/www/*, read, allow",
			expected: []string{"p", "httpd_t", "/var/www/*", "read", "allow"},
		},
		{
			name:     "CSV with quotes",
			line:     `p, "httpd_t", "/var/www/*", read, allow`,
			expected: []string{"p", "httpd_t", "/var/www/*", "read", "allow"},
		},
		{
			name:     "CSV with commas in quotes",
			line:     `p, httpd_t, "/var/www,html/*", read, allow`,
			expected: []string{"p", "httpd_t", "/var/www,html/*", "read", "allow"},
		},
		{
			name:     "CSV with spaces",
			line:     "p,  httpd_t  ,  /var/www/*  ,  read  ,  allow  ",
			expected: []string{"p", "httpd_t", "/var/www/*", "read", "allow"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseCSVLine(tt.line)
			if len(result) != len(tt.expected) {
				t.Errorf("Expected %d fields, got %d", len(tt.expected), len(result))
				return
			}
			for i := range result {
				if result[i] != tt.expected[i] {
					t.Errorf("Field %d: expected %q, got %q", i, tt.expected[i], result[i])
				}
			}
		})
	}
}

// TestParseError tests the ParseError type
func TestParseError(t *testing.T) {
	err := &ParseError{
		File:    "test.conf",
		Line:    10,
		Message: "invalid syntax",
	}

	expected := "test.conf:10: invalid syntax"
	if err.Error() != expected {
		t.Errorf("Expected error message %q, got %q", expected, err.Error())
	}
}

// Helper function to check if a string contains a substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && findSubstring(s, substr)))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
