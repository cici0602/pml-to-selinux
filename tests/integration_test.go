package main

import (
	"strings"
	"testing"

	"github.com/cici0602/pml-to-selinux/models"
	"github.com/cici0602/pml-to-selinux/selinux"
)

// TestFullPolicyGeneration tests complete PML to SELinux policy generation
func TestFullPolicyGeneration(t *testing.T) {
	policy := &models.SELinuxPolicy{
		ModuleName: "httpd_custom",
		Version:    "1.0.0",
		Types: []models.TypeDeclaration{
			{TypeName: "httpd_t", Attributes: []string{"domain"}},
			{TypeName: "httpd_exec_t", Attributes: []string{"file_type", "exec_type"}},
			{TypeName: "httpd_config_t"},
			{TypeName: "httpd_log_t"},
		},
		Rules: []models.AllowRule{
			{
				SourceType:  "httpd_t",
				TargetType:  "httpd_config_t",
				Class:       "file",
				Permissions: []string{"read", "open"},
			},
			{
				SourceType:  "httpd_t",
				TargetType:  "httpd_log_t",
				Class:       "file",
				Permissions: []string{"write", "append", "create"},
			},
		},
		Transitions: []models.TypeTransition{
			{
				SourceType: "init_t",
				TargetType: "httpd_exec_t",
				Class:      "process",
				NewType:    "httpd_t",
			},
		},
		FileContexts: []models.FileContext{
			{
				PathPattern: "/usr/sbin/httpd",
				FileType:    "httpd_exec_t",
			},
			{
				PathPattern: "/etc/httpd(/.*)?",
				FileType:    "httpd_config_t",
			},
			{
				PathPattern: "/var/log/httpd(/.*)?",
				FileType:    "httpd_log_t",
			},
		},
	}

	// Generate .te file
	teContent, err := selinux.GenerateTE(policy)
	if err != nil {
		t.Fatalf("GenerateTE() error = %v", err)
	}

	// Generate .fc file
	fcContent, err := selinux.GenerateFC(policy)
	if err != nil {
		t.Fatalf("GenerateFC() error = %v", err)
	}

	// Validate .te file structure
	validateTEFile(t, teContent)

	// Validate .fc file structure
	validateFCFile(t, fcContent)

	// Validate cross-references
	validateCrossReferences(t, teContent, fcContent, policy)
}

// TestComplexPolicyWithBooleans tests policy with conditional blocks
func TestComplexPolicyWithBooleans(t *testing.T) {
	policy := &models.SELinuxPolicy{
		ModuleName: "webapp",
		Version:    "2.0.0",
		Types: []models.TypeDeclaration{
			{TypeName: "webapp_t"},
			{TypeName: "webapp_db_t"},
			{TypeName: "webapp_cache_t"},
		},
			{
				Name:         "webapp_can_network",
				DefaultValue: false,
				Description:  "Allow webapp to connect to network",
			},
			{
				Name:         "webapp_use_nfs",
				DefaultValue: false,
				Description:  "Allow webapp to use NFS",
			},
		},
			{
				BooleanExpr: "webapp_can_network",
				ThenRules: []models.AllowRule{
					{
						SourceType:  "webapp_t",
						TargetType:  "port_t",
						Class:       "tcp_socket",
						Permissions: []string{"name_connect"},
					},
				},
			},
			{
				BooleanExpr: "webapp_use_nfs",
				ThenRules: []models.AllowRule{
					{
						SourceType:  "webapp_t",
						TargetType:  "nfs_t",
						Class:       "dir",
						Permissions: []string{"read", "search"},
					},
				},
				ElseRules: []models.AllowRule{
					{
						SourceType:  "webapp_t",
						TargetType:  "webapp_cache_t",
						Class:       "dir",
						Permissions: []string{"read", "search"},
					},
				},
			},
		},
		Rules: []models.AllowRule{
			{
				SourceType:  "webapp_t",
				TargetType:  "webapp_db_t",
				Class:       "file",
				Permissions: []string{"read", "write"},
			},
		},
		FileContexts: []models.FileContext{
			{
				PathPattern: "/opt/webapp/bin/app",
				FileType:    "webapp_t",
			},
		},
	}

	teContent, err := selinux.GenerateTE(policy)
	if err != nil {
		t.Fatalf("GenerateTE() error = %v", err)
	}

	// Validate boolean declarations
	if !strings.Contains(teContent, "gen_tunable(webapp_can_network, false)") {
		t.Error("Missing webapp_can_network boolean")
	}

	if !strings.Contains(teContent, "gen_tunable(webapp_use_nfs, false)") {
		t.Error("Missing webapp_use_nfs boolean")
	}

	// Validate conditional blocks
	if !strings.Contains(teContent, "if (webapp_can_network) {") {
		t.Error("Missing webapp_can_network conditional")
	}

	if !strings.Contains(teContent, "if (webapp_use_nfs) {") {
		t.Error("Missing webapp_use_nfs conditional")
	}

	if !strings.Contains(teContent, "} else {") {
		t.Error("Missing else clause")
	}
}

// TestMinimalPolicy tests minimal valid policy
func TestMinimalPolicy(t *testing.T) {
	policy := &models.SELinuxPolicy{
		ModuleName: "minimal",
		Version:    "1.0.0",
		Types: []models.TypeDeclaration{
			{TypeName: "minimal_t"},
		},
	}

	teContent, err := selinux.GenerateTE(policy)
	if err != nil {
		t.Fatalf("GenerateTE() error = %v", err)
	}

	fcContent, err := selinux.GenerateFC(policy)
	if err != nil {
		t.Fatalf("GenerateFC() error = %v", err)
	}

	// Should have basic structure
	if !strings.Contains(teContent, "policy_module(minimal, 1.0.0)") {
		t.Error("Missing policy_module declaration")
	}

	if !strings.Contains(teContent, "type minimal_t;") {
		t.Error("Missing type declaration")
	}

	// FC file should be minimal (no contexts)
	lines := strings.Split(strings.TrimSpace(fcContent), "\n")
	validLines := 0
	for _, line := range lines {
		if line != "" && !strings.HasPrefix(line, "#") {
			validLines++
		}
	}
	if validLines > 0 {
		t.Errorf("Minimal policy should have no file contexts, found %d", validLines)
	}
}

// Helper functions

func validateTEFile(t *testing.T, content string) {
	t.Helper()

	// Must have policy_module
	if !strings.Contains(content, "policy_module(") {
		t.Error("TE file missing policy_module declaration")
	}

	// Must have proper structure sections
	requiredSections := []string{
		"# Type Declarations",
		"# Allow Rules",
	}

	for _, section := range requiredSections {
		if !strings.Contains(content, section) {
			t.Errorf("TE file missing section: %s", section)
		}
	}

	// Check for proper formatting (no trailing whitespace on empty lines)
	lines := strings.Split(content, "\n")
	for i, line := range lines {
		if line != strings.TrimRight(line, " \t") {
			t.Errorf("Line %d has trailing whitespace", i+1)
		}
	}
}

func validateFCFile(t *testing.T, content string) {
	t.Helper()

	// FC file should have context entries
	lines := strings.Split(strings.TrimSpace(content), "\n")
	contextCount := 0
	for _, line := range lines {
		if line != "" && !strings.HasPrefix(line, "#") {
			contextCount++
			// Each line should have format: path [filespec] context
			parts := strings.Fields(line)
			if len(parts) < 2 {
				t.Errorf("Invalid FC line format: %s", line)
			}
		}
	}

	if contextCount == 0 {
		t.Error("FC file has no file contexts")
	}
}

func validateCrossReferences(t *testing.T, teContent, fcContent string, policy *models.SELinuxPolicy) {
	t.Helper()

	// All types in FileContexts should be declared in TE file
	for _, fc := range policy.FileContexts {
		typeDecl := "type " + fc.FileType
		if !strings.Contains(teContent, typeDecl) {
			t.Errorf("Type %s used in FC but not declared in TE", fc.FileType)
		}
	}

	// All file contexts should be in FC file
	for _, fc := range policy.FileContexts {
		if !strings.Contains(fcContent, fc.PathPattern) {
			t.Errorf("File context %s not found in FC file", fc.PathPattern)
		}
	}
}
