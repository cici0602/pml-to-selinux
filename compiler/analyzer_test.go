package compiler

import (
	"testing"

	"github.com/cici0602/pml-to-selinux/models"
)

// TestValidateModel tests model validation
func TestValidateModel(t *testing.T) {
	tests := []struct {
		name    string
		model   *models.PMLModel
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid complete model",
			model: &models.PMLModel{
				RequestDefinition: map[string][]string{
					"r": {"sub", "obj", "act", "class"},
				},
				PolicyDefinition: map[string][]string{
					"p": {"sub", "obj", "act", "class", "eft"},
				},
				RoleDefinition: map[string][]string{
					"g": {"_", "_"},
				},
				Matchers: "r.sub == p.sub",
				Effect:   "some(where (p.eft == allow))",
			},
			wantErr: false,
		},
		{
			name: "missing request_definition",
			model: &models.PMLModel{
				PolicyDefinition: map[string][]string{
					"p": {"sub", "obj", "act", "class", "eft"},
				},
				Matchers: "r.sub == p.sub",
				Effect:   "some(where (p.eft == allow))",
			},
			wantErr: true,
			errMsg:  "request_definition is missing",
		},
		{
			name: "missing r in request_definition",
			model: &models.PMLModel{
				RequestDefinition: map[string][]string{},
				PolicyDefinition: map[string][]string{
					"p": {"sub", "obj", "act", "class", "eft"},
				},
				Matchers: "r.sub == p.sub",
				Effect:   "some(where (p.eft == allow))",
			},
			wantErr: true,
			errMsg:  "request_definition is missing",
		},
		{
			name: "empty request_definition r",
			model: &models.PMLModel{
				RequestDefinition: map[string][]string{
					"r": {},
				},
				PolicyDefinition: map[string][]string{
					"p": {"sub", "obj", "act", "class", "eft"},
				},
				Matchers: "r.sub == p.sub",
				Effect:   "some(where (p.eft == allow))",
			},
			wantErr: true,
			errMsg:  "request_definition 'r' is empty",
		},
		{
			name: "missing policy_definition",
			model: &models.PMLModel{
				RequestDefinition: map[string][]string{
					"r": {"sub", "obj", "act", "class"},
				},
				Matchers: "r.sub == p.sub",
				Effect:   "some(where (p.eft == allow))",
			},
			wantErr: true,
			errMsg:  "policy_definition is missing",
		},
		{
			name: "missing matchers",
			model: &models.PMLModel{
				RequestDefinition: map[string][]string{
					"r": {"sub", "obj", "act", "class"},
				},
				PolicyDefinition: map[string][]string{
					"p": {"sub", "obj", "act", "class", "eft"},
				},
				Effect: "some(where (p.eft == allow))",
			},
			wantErr: true,
			errMsg:  "matchers section is missing",
		},
		{
			name: "missing policy_effect",
			model: &models.PMLModel{
				RequestDefinition: map[string][]string{
					"r": {"sub", "obj", "act", "class"},
				},
				PolicyDefinition: map[string][]string{
					"p": {"sub", "obj", "act", "class", "eft"},
				},
				Matchers: "r.sub == p.sub",
			},
			wantErr: true,
			errMsg:  "policy_effect section is missing",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pml := &models.ParsedPML{
				Model:    tt.model,
				Policies: []models.Policy{},
				Roles:    []models.RoleRelation{},
			}
			analyzer := NewAnalyzer(pml)

			err := analyzer.validateModel()

			if (err != nil) != tt.wantErr {
				t.Errorf("validateModel() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr && err != nil && tt.errMsg != "" {
				if !contains(err.Error(), tt.errMsg) {
					t.Errorf("validateModel() error = %v, should contain %q", err, tt.errMsg)
				}
			}
		})
	}
}

// TestValidatePolicies tests policy validation
func TestValidatePolicies(t *testing.T) {
	tests := []struct {
		name     string
		policies []models.Policy
		wantErr  bool
		errMsg   string
	}{
		{
			name: "valid policies",
			policies: []models.Policy{
				{Subject: "httpd_t", Object: "/var/www/*", Action: "read", Class: "file", Effect: "allow"},
				{Subject: "httpd_t", Object: "/var/log/*", Action: "write", Class: "file", Effect: "allow"},
				{Subject: "httpd_t", Object: "/usr/bin/*", Action: "write", Class: "file", Effect: "deny"},
			},
			wantErr: false,
		},
		{
			name: "empty subject",
			policies: []models.Policy{
				{Subject: "", Object: "/var/www/*", Action: "read", Class: "file", Effect: "allow"},
			},
			wantErr: true,
			errMsg:  "subject cannot be empty",
		},
		{
			name: "empty object",
			policies: []models.Policy{
				{Subject: "httpd_t", Object: "", Action: "read", Class: "file", Effect: "allow"},
			},
			wantErr: true,
			errMsg:  "object cannot be empty",
		},
		{
			name: "empty action",
			policies: []models.Policy{
				{Subject: "httpd_t", Object: "/var/www/*", Action: "", Class: "file", Effect: "allow"},
			},
			wantErr: true,
			errMsg:  "action cannot be empty",
		},
		{
			name: "empty class",
			policies: []models.Policy{
				{Subject: "httpd_t", Object: "/var/www/*", Action: "read", Class: "", Effect: "allow"},
			},
			wantErr: true,
			errMsg:  "class cannot be empty",
		},
		{
			name: "invalid effect",
			policies: []models.Policy{
				{Subject: "httpd_t", Object: "/var/www/*", Action: "read", Class: "file", Effect: "maybe"},
			},
			wantErr: true,
			errMsg:  "invalid effect",
		},
		{
			name: "invalid path pattern",
			policies: []models.Policy{
				{Subject: "httpd_t", Object: "var/www/*", Action: "read", Class: "file", Effect: "allow"},
			},
			wantErr: true,
			errMsg:  "invalid object pattern",
		},
		{
			name: "valid special object type",
			policies: []models.Policy{
				{Subject: "httpd_t", Object: "tcp_socket", Action: "bind", Class: "tcp_socket", Effect: "allow"},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pml := &models.ParsedPML{
				Model: &models.PMLModel{
					RequestDefinition: map[string][]string{"r": {"sub", "obj", "act", "class"}},
					PolicyDefinition:  map[string][]string{"p": {"sub", "obj", "act", "class", "eft"}},
					Matchers:          "m",
					Effect:            "e",
				},
				Policies: tt.policies,
				Roles:    []models.RoleRelation{},
			}
			analyzer := NewAnalyzer(pml)

			err := analyzer.validatePolicies()

			if (err != nil) != tt.wantErr {
				t.Errorf("validatePolicies() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr && err != nil && tt.errMsg != "" {
				if !contains(err.Error(), tt.errMsg) {
					t.Errorf("validatePolicies() error = %v, should contain %q", err, tt.errMsg)
				}
			}
		})
	}
}

// TestDetectConflicts tests policy conflict detection
func TestDetectConflicts(t *testing.T) {
	tests := []struct {
		name           string
		policies       []models.Policy
		expectConflict bool
		conflictCount  int
	}{
		{
			name: "no conflicts - different subjects",
			policies: []models.Policy{
				{Subject: "httpd_t", Object: "/var/www/*", Action: "read", Class: "file", Effect: "allow"},
				{Subject: "nginx_t", Object: "/var/www/*", Action: "read", Class: "file", Effect: "deny"},
			},
			expectConflict: false,
			conflictCount:  0,
		},
		{
			name: "no conflicts - different actions",
			policies: []models.Policy{
				{Subject: "httpd_t", Object: "/var/www/*", Action: "read", Class: "file", Effect: "allow"},
				{Subject: "httpd_t", Object: "/var/www/*", Action: "write", Class: "file", Effect: "deny"},
			},
			expectConflict: false,
			conflictCount:  0,
		},
		{
			name: "conflict - same subject, object, action, class",
			policies: []models.Policy{
				{Subject: "httpd_t", Object: "/var/www/*", Action: "read", Class: "file", Effect: "allow"},
				{Subject: "httpd_t", Object: "/var/www/*", Action: "read", Class: "file", Effect: "deny"},
			},
			expectConflict: true,
			conflictCount:  1,
		},
		{
			name: "conflict - overlapping paths",
			policies: []models.Policy{
				{Subject: "httpd_t", Object: "/var/www/*", Action: "write", Class: "file", Effect: "allow"},
				{Subject: "httpd_t", Object: "/var/www/html/*", Action: "write", Class: "file", Effect: "deny"},
			},
			expectConflict: true,
			conflictCount:  1,
		},
		{
			name: "multiple conflicts",
			policies: []models.Policy{
				{Subject: "httpd_t", Object: "/var/www/*", Action: "read", Class: "file", Effect: "allow"},
				{Subject: "httpd_t", Object: "/var/www/*", Action: "read", Class: "file", Effect: "deny"},
				{Subject: "httpd_t", Object: "/var/log/*", Action: "write", Class: "file", Effect: "allow"},
				{Subject: "httpd_t", Object: "/var/log/*", Action: "write", Class: "file", Effect: "deny"},
			},
			expectConflict: true,
			conflictCount:  2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pml := &models.ParsedPML{
				Model: &models.PMLModel{
					RequestDefinition: map[string][]string{"r": {"sub", "obj", "act", "class"}},
					PolicyDefinition:  map[string][]string{"p": {"sub", "obj", "act", "class", "eft"}},
					Matchers:          "m",
					Effect:            "e",
				},
				Policies: tt.policies,
				Roles:    []models.RoleRelation{},
			}
			analyzer := NewAnalyzer(pml)

			conflicts := analyzer.detectConflicts()

			if tt.expectConflict && len(conflicts) == 0 {
				t.Error("Expected conflicts but none were found")
			}

			if !tt.expectConflict && len(conflicts) > 0 {
				t.Errorf("Expected no conflicts but found %d", len(conflicts))
			}

			if tt.conflictCount > 0 && len(conflicts) != tt.conflictCount {
				t.Errorf("Expected %d conflicts, got %d", tt.conflictCount, len(conflicts))
			}
		})
	}
}

// TestGenerateStats tests statistics generation
func TestGenerateStats(t *testing.T) {
	policies := []models.Policy{
		{Subject: "httpd_t", Object: "/var/www/*", Action: "read", Class: "file", Effect: "allow"},
		{Subject: "httpd_t", Object: "/var/www/*", Action: "write", Class: "file", Effect: "allow"},
		{Subject: "httpd_t", Object: "/var/log/*", Action: "write", Class: "file", Effect: "allow"},
		{Subject: "nginx_t", Object: "/var/www/*", Action: "read", Class: "file", Effect: "allow"},
		{Subject: "httpd_t", Object: "/usr/bin/*", Action: "write", Class: "file", Effect: "deny"},
	}

	roles := []models.RoleRelation{
		{Member: "user_u", Role: "user_r"},
		{Member: "system_u", Role: "system_r"},
	}

	pml := &models.ParsedPML{
		Model: &models.PMLModel{
			RequestDefinition: map[string][]string{"r": {"sub", "obj", "act", "class"}},
			PolicyDefinition:  map[string][]string{"p": {"sub", "obj", "act", "class", "eft"}},
			Matchers:          "m",
			Effect:            "e",
		},
		Policies: policies,
		Roles:    roles,
	}

	analyzer := NewAnalyzer(pml)
	analyzer.generateStats()
	stats := analyzer.GetStats()

	// Check basic counts
	if stats.TotalPolicies != 5 {
		t.Errorf("Expected 5 total policies, got %d", stats.TotalPolicies)
	}

	if stats.AllowRules != 4 {
		t.Errorf("Expected 4 allow rules, got %d", stats.AllowRules)
	}

	if stats.DenyRules != 1 {
		t.Errorf("Expected 1 deny rule, got %d", stats.DenyRules)
	}

	if stats.UniqueSubjects != 2 {
		t.Errorf("Expected 2 unique subjects, got %d", stats.UniqueSubjects)
	}

	if stats.UniqueObjects != 3 {
		t.Errorf("Expected 3 unique objects, got %d", stats.UniqueObjects)
	}

	if stats.UniqueActions != 2 {
		t.Errorf("Expected 2 unique actions, got %d", stats.UniqueActions)
	}

	if stats.RoleRelations != 2 {
		t.Errorf("Expected 2 role relations, got %d", stats.RoleRelations)
	}

	// Check subject type counts
	if stats.SubjectTypes["httpd_t"] != 4 {
		t.Errorf("Expected 4 rules for httpd_t, got %d", stats.SubjectTypes["httpd_t"])
	}

	if stats.SubjectTypes["nginx_t"] != 1 {
		t.Errorf("Expected 1 rule for nginx_t, got %d", stats.SubjectTypes["nginx_t"])
	}
}

// TestAnalyzeIntegration tests the full analysis workflow
func TestAnalyzeIntegration(t *testing.T) {
	pml := &models.ParsedPML{
		Model: &models.PMLModel{
			RequestDefinition: map[string][]string{
				"r": {"sub", "obj", "act", "class"},
			},
			PolicyDefinition: map[string][]string{
				"p": {"sub", "obj", "act", "class", "eft"},
			},
			RoleDefinition: map[string][]string{
				"g": {"_", "_"},
			},
			Matchers: "r.sub == p.sub && r.obj == p.obj",
			Effect:   "some(where (p.eft == allow))",
		},
		Policies: []models.Policy{
			{Subject: "httpd_t", Object: "/var/www/*", Action: "read", Class: "file", Effect: "allow"},
			{Subject: "httpd_t", Object: "/var/www/*", Action: "write", Class: "file", Effect: "allow"},
			{Subject: "httpd_t", Object: "/var/log/*", Action: "write", Class: "file", Effect: "allow"},
		},
		Roles: []models.RoleRelation{
			{Member: "user_u", Role: "user_r"},
		},
	}

	analyzer := NewAnalyzer(pml)
	err := analyzer.Analyze()

	if err != nil {
		t.Errorf("Analyze() error = %v", err)
	}

	stats := analyzer.GetStats()
	if stats.TotalPolicies != 3 {
		t.Errorf("Expected 3 total policies, got %d", stats.TotalPolicies)
	}
}

// TestPathsOverlap tests path overlap detection
func TestPathsOverlap(t *testing.T) {
	tests := []struct {
		name   string
		path1  string
		path2  string
		expect bool
	}{
		{
			name:   "exact match",
			path1:  "/var/www/html",
			path2:  "/var/www/html",
			expect: true,
		},
		{
			name:   "wildcard match - path1 wildcard",
			path1:  "/var/www/*",
			path2:  "/var/www/html",
			expect: true,
		},
		{
			name:   "wildcard match - path2 wildcard",
			path1:  "/var/www/html",
			path2:  "/var/www/*",
			expect: true,
		},
		{
			name:   "no overlap - different base",
			path1:  "/var/www/*",
			path2:  "/usr/bin/*",
			expect: false,
		},
		{
			name:   "same directory wildcards",
			path1:  "/var/www/*.html",
			path2:  "/var/www/*.php",
			expect: true,
		},
	}

	analyzer := NewAnalyzer(&models.ParsedPML{})

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := analyzer.pathsOverlap(tt.path1, tt.path2)
			if result != tt.expect {
				t.Errorf("pathsOverlap(%q, %q) = %v, expected %v", tt.path1, tt.path2, result, tt.expect)
			}
		})
	}
}
