package compiler

import (
	"testing"

	"github.com/cici0602/pml-to-selinux/models"
)

func TestGenerator_Generate(t *testing.T) {
	pml := &models.ParsedPML{
		Model: &models.PMLModel{
			RequestDefinition: map[string][]string{
				"r": {"sub", "obj", "act", "cls"},
			},
			PolicyDefinition: map[string][]string{
				"p": {"sub", "obj", "act", "cls", "eft"},
			},
			Matchers: "r.sub == p.sub && r.obj == p.obj && r.act == p.act && r.cls == p.cls",
			Effect:   "some(where (p.eft == allow))",
		},
		Policies: []models.Policy{
			{
				Subject: "httpd",
				Object:  "/var/www/html/*",
				Action:  "read",
				Class:   "file",
				Effect:  "allow",
			},
			{
				Subject: "httpd",
				Object:  "/var/log/httpd/*",
				Action:  "write",
				Class:   "file",
				Effect:  "allow",
			},
		},
		Roles: []models.RoleRelation{},
	}

	generator := NewGenerator(pml, "httpd")
	policy, err := generator.Generate()

	if err != nil {
		t.Errorf("Generate() error = %v", err)
		return
	}
	if policy == nil {
		t.Error("Generate() returned nil policy")
		return
	}
	if policy.ModuleName != "httpd" {
		t.Errorf("ModuleName = %s, want httpd", policy.ModuleName)
	}
	if policy.Version != "1.0.0" {
		t.Errorf("Version = %s, want 1.0.0", policy.Version)
	}
	if len(policy.Types) == 0 {
		t.Error("should have at least one type")
	}
	if len(policy.Rules) == 0 {
		t.Error("should have at least one rule")
	}
	if len(policy.FileContexts) == 0 {
		t.Error("should have file contexts")
	}
}

func TestGenerator_InferModuleName(t *testing.T) {
	pml := &models.ParsedPML{
		Model: &models.PMLModel{},
		Policies: []models.Policy{
			{Subject: "nginx_process", Object: "/var/www/*", Action: "read", Class: "file", Effect: "allow"},
		},
	}

	generator := NewGenerator(pml, "")
	policy, err := generator.Generate()

	if err != nil {
		t.Errorf("Generate() error = %v", err)
		return
	}
	if policy.ModuleName != "nginx" {
		t.Errorf("ModuleName = %s, want nginx", policy.ModuleName)
	}
}

func TestGenerator_ActionToPermissions(t *testing.T) {
	pml := &models.ParsedPML{
		Model:    &models.PMLModel{},
		Policies: []models.Policy{},
	}
	gen := NewGenerator(pml, "test")

	tests := []struct {
		name              string
		action            string
		expectedClass     string
		expectedPermsMin  int // Minimum expected permissions
	}{
		{
			name:             "read",
			action:           "read",
			expectedClass:    "file",
			expectedPermsMin: 2, // at least "read" and "open"
		},
		{
			name:             "write",
			action:           "write",
			expectedClass:    "file",
			expectedPermsMin: 2, // at least "write" and "open"
		},
		{
			name:             "execute",
			action:           "execute",
			expectedClass:    "file",
			expectedPermsMin: 2, // at least "execute" and "read"
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			class, perms := gen.actionToPermissions(tt.action)

			if class != tt.expectedClass {
				t.Errorf("actionToPermissions(%s) class = %s, want %s",
					tt.action, class, tt.expectedClass)
			}

			if len(perms) < tt.expectedPermsMin {
				t.Errorf("actionToPermissions(%s) perms count = %d, want at least %d",
					tt.action, len(perms), tt.expectedPermsMin)
			}
		})
	}
}
