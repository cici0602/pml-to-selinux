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
	generator := &Generator{typeMapper: nil, pathMapper: nil}

	tests := []struct {
		action    string
		wantClass string
		wantPerms []string
	}{
		{"read", "file", []string{"read", "open", "getattr"}},
		{"write", "file", []string{"write", "append", "open"}},
		{"execute", "file", []string{"execute", "execute_no_trans"}},
		{"create", "file", []string{"create", "write", "open"}},
		{"delete", "file", []string{"unlink"}},
		{"search", "dir", []string{"search", "open"}},
		{"list", "dir", []string{"read", "search", "open"}},
	}

	for _, tt := range tests {
		t.Run(tt.action, func(t *testing.T) {
			class, perms := generator.actionToPermissions(tt.action)
			if class != tt.wantClass {
				t.Errorf("actionToPermissions(%s) class = %s, want %s", tt.action, class, tt.wantClass)
			}
			if len(perms) != len(tt.wantPerms) {
				t.Errorf("actionToPermissions(%s) perms length = %d, want %d", tt.action, len(perms), len(tt.wantPerms))
				return
			}
			for i, perm := range perms {
				if perm != tt.wantPerms[i] {
					t.Errorf("actionToPermissions(%s) perms[%d] = %s, want %s", tt.action, i, perm, tt.wantPerms[i])
				}
			}
		})
	}
}
