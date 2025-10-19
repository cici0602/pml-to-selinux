package selinux

import (
"strings"
"testing"

"github.com/cici0602/pml-to-selinux/models"
)

func TestTEGenerator_Generate(t *testing.T) {
	policy := &models.SELinuxPolicy{
		ModuleName: "httpd",
		Version:    "1.0.0",
		Types: []models.TypeDeclaration{
			{
				TypeName:   "httpd_t",
				Attributes: []string{"domain"},
			},
			{
				TypeName:   "httpd_exec_t",
				Attributes: []string{"file_type", "exec_type"},
			},
		},
		Rules: []models.AllowRule{
			{
				SourceType:  "httpd_t",
				TargetType:  "httpd_exec_t",
				Class:       "file",
				Permissions: []string{"read", "execute", "open"},
			},
		},
	}

	generator := NewTEGenerator(policy)
	result, err := generator.Generate()

	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	if !strings.Contains(result, "policy_module(httpd, 1.0.0)") {
		t.Error("Missing policy_module declaration")
	}

	if !strings.Contains(result, "type httpd_t") {
		t.Error("Missing httpd_t type declaration")
	}

	if !strings.Contains(result, "allow httpd_t httpd_exec_t:file") {
		t.Error("Missing allow rule")
	}
}

func TestTEGenerator_EmptyPolicy(t *testing.T) {
	policy := &models.SELinuxPolicy{
		ModuleName: "empty",
		Version:    "1.0.0",
	}

	generator := NewTEGenerator(policy)
	result, err := generator.Generate()

	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	if !strings.Contains(result, "policy_module(empty, 1.0.0)") {
		t.Error("Missing policy_module declaration")
	}
}
