package compiler

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cici0602/pml-to-selinux/models"
)

// TestParserEdgeCases tests edge cases and error handling
func TestParserEdgeCases(t *testing.T) {
	tests := []struct {
		name        string
		modelData   string
		policyData  string
		wantErr     bool
		errContains string
	}{
		{
			name:        "empty model file",
			modelData:   "",
			policyData:  "p, httpd_t, /var/www/*, read, allow",
			wantErr:     true,
			errContains: "empty model file",
		},
		{
			name: "empty policy file",
			modelData: `[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act, eft

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == p.sub`,
			policyData: "",
			wantErr:    false, // Empty policy is allowed
		},
		{
			name: "malformed CSV line",
			modelData: `[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act, eft

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == p.sub`,
			policyData:  "p, httpd_t, /var/www/*, read", // Missing fields
			wantErr:     true,
			errContains: "policy rule expects 5 fields",
		},
		{
			name: "invalid effect",
			modelData: `[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act, eft

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == p.sub`,
			policyData:  "p, httpd_t, /var/www/*, read, invalid_effect",
			wantErr:     true,
			errContains: "invalid effect",
		},
		{
			name: "boolean with invalid value",
			modelData: `[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act, eft

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == p.sub`,
			policyData: `p, httpd_t, /var/www/*, read, allow
g2, bool:maybe, httpd_enable_network`,
			wantErr: false, // Parser should handle this, decoder will validate
		},
		{
			name: "very long path",
			modelData: `[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act, eft

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == p.sub`,
			policyData: "p, httpd_t, " + generateLongPath(1000) + ", read, allow",
			wantErr:    false, // Should handle long paths
		},
		{
			name: "special characters in path",
			modelData: `[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act, eft

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == p.sub`,
			policyData: `p, httpd_t, "/var/www/html with spaces/file-name.ext", read, allow`,
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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
		})
	}
}

// TestDecoderEdgeCases tests decoder edge cases
func TestDecoderEdgeCases(t *testing.T) {
	tests := []struct {
		name        string
		policies    []string
		roles       []string
		wantErr     bool
		errContains string
	}{
		{
			name:     "transition without proper fields",
			policies: []string{"p2, httpd_t, /bin/httpd, transition, invalid"},
			roles:    []string{},
			wantErr:  false, // Should handle gracefully
		},
		{
			name:     "conditional policy with complex condition",
			policies: []string{"p, httpd_t, /var/www/*?cond=httpd_enable_network&&debug_mode, read, file, allow"},
			roles:    []string{},
			wantErr:  false,
		},
		{
			name:     "malformed boolean role",
			policies: []string{},
			roles:    []string{"g2, notbool:true, httpd_enable_network"},
			wantErr:  false, // Will be treated as type attribute
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock PML
			mockPML := createMockPML(tt.policies, tt.roles)

			parser := &Parser{}
			_, err := parser.Decode(mockPML)

			if (err != nil) != tt.wantErr {
				t.Errorf("Decode() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.errContains != "" && err != nil {
				if !contains(err.Error(), tt.errContains) {
					t.Errorf("Decode() error = %v, should contain %q", err, tt.errContains)
				}
			}
		})
	}
}

// Helper function to generate long paths for testing
func generateLongPath(length int) string {
	path := "/very"
	for i := 0; i < length/10; i++ {
		path += "/long/path"
	}
	return path + "/*"
}

// Helper function to create mock PML for testing
func createMockPML(policies, roles []string) *models.ParsedPML {
	mockModel := &models.PMLModel{
		RequestDefinition: map[string][]string{
			"r": {"sub", "obj", "act", "cls"},
		},
		PolicyDefinition: map[string][]string{
			"p": {"sub", "obj", "act", "cls", "eft"},
		},
		Matchers: "r.sub == p.sub",
		Effect:   "some(where (p.eft == allow))",
	}

	var policyList []models.Policy
	for _, p := range policies {
		fields := parseCSVLine(p)
		if len(fields) >= 6 {
			// Parse policy: type, sub, obj, act, eft (standard Casbin triple)
			if len(fields) != 5 {
				continue // Skip invalid policies
			}
			policy := models.Policy{
				Type:    fields[0],
				Subject: fields[1],
				Object:  fields[2],
				Action:  fields[3],
				Effect:  fields[4],
			}
			policyList = append(policyList, policy)
		}
	}

	var roleList []models.RoleRelation
	for _, r := range roles {
		fields := parseCSVLine(r)
		if len(fields) >= 3 {
			role := models.RoleRelation{
				Type:   fields[0],
				Member: fields[1],
				Role:   fields[2],
			}
			roleList = append(roleList, role)
		}
	}

	return &models.ParsedPML{
		Model:    mockModel,
		Policies: policyList,
		Roles:    roleList,
	}
}
