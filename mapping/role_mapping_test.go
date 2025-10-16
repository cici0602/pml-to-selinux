package mapping

import (
	"strings"
	"testing"

	"github.com/cici0602/pml-to-selinux/models"
)

func TestMapRole(t *testing.T) {
	rm := NewRoleMapper("myapp")

	tests := []struct {
		name     string
		pmlRole  string
		expected string
	}{
		{"User role", "user", "user_r"},
		{"Staff role", "staff", "staff_r"},
		{"System admin", "sysadm", "sysadm_r"},
		{"Custom role", "webapp_admin", "myapp_webapp_admin_r"},
		{"Role with spaces", "web admin", "myapp_web_admin_r"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := rm.MapRole(tt.pmlRole)
			if result != tt.expected {
				t.Errorf("MapRole(%s) = %s, want %s", tt.pmlRole, result, tt.expected)
			}
		})
	}
}

func TestGenerateRoleName(t *testing.T) {
	rm := NewRoleMapper("httpd")

	tests := []struct {
		name     string
		pmlRole  string
		expected string
	}{
		{"Simple role", "admin", "httpd_admin_r"},
		{"Role with suffix", "webapp_role", "httpd_webapp_r"},
		{"Group suffix", "users_group", "httpd_users_r"},
		{"With dashes", "web-admin", "httpd_web_admin_r"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := rm.generateRoleName(tt.pmlRole)
			if result != tt.expected {
				t.Errorf("generateRoleName(%s) = %s, want %s", tt.pmlRole, result, tt.expected)
			}
		})
	}
}

func TestBuildRoleHierarchy(t *testing.T) {
	rm := NewRoleMapper("app")

	relations := []models.RoleRelation{
		{Member: "alice", Role: "admin"},
		{Member: "bob", Role: "user"},
		{Member: "admin", Role: "superadmin"},
	}

	rm.BuildRoleHierarchy(relations)

	// Check alice is member of admin
	parents := rm.GetRoleParents("alice")
	if len(parents) == 0 {
		t.Error("alice should have parent roles")
	}

	// Check admin's parents (should include superadmin)
	adminParents := rm.GetRoleParents("admin")
	hasSuper := false
	for _, p := range adminParents {
		if p == "app_superadmin_r" {
			hasSuper = true
			break
		}
	}
	if !hasSuper {
		t.Error("admin should inherit from superadmin")
	}
}

func TestGenerateRoleAllowRules(t *testing.T) {
	rm := NewRoleMapper("app")

	relations := []models.RoleRelation{
		{Member: "user", Role: "staff"},
		{Member: "staff", Role: "sysadm"},
	}

	rm.BuildRoleHierarchy(relations)
	rules := rm.GenerateRoleAllowRules()

	if len(rules) < 2 {
		t.Errorf("Expected at least 2 role allow rules, got %d", len(rules))
	}

	// Check for expected rules
	expectedRules := map[string]bool{
		"allow user_r staff_r;":   false,
		"allow staff_r sysadm_r;": false,
	}

	for _, rule := range rules {
		if _, exists := expectedRules[rule]; exists {
			expectedRules[rule] = true
		}
	}

	for rule, found := range expectedRules {
		if !found {
			t.Errorf("Expected rule not found: %s", rule)
		}
	}
}

func TestInferRoleFromDomain(t *testing.T) {
	rm := NewRoleMapper("app")

	tests := []struct {
		name     string
		domain   string
		expected string
	}{
		{"System domain", "kernel_t", "system_r"},
		{"User domain", "user_t", "user_r"},
		{"Admin domain", "sysadm_t", "sysadm_r"},
		{"Daemon domain", "httpd_t", "system_r"},
		{"Generic type", "webapp_t", "system_r"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := rm.InferRoleFromDomain(tt.domain)
			if result != tt.expected {
				t.Errorf("InferRoleFromDomain(%s) = %s, want %s", tt.domain, result, tt.expected)
			}
		})
	}
}

func TestUserToSELinuxUser(t *testing.T) {
	rm := NewRoleMapper("app")

	tests := []struct {
		name     string
		pmlUser  string
		expected string
	}{
		{"Root user", "root", "root"},
		{"Admin user", "admin", "root"},
		{"System user", "system", "system_u"},
		{"Regular user", "john", "user_u"},
		{"Unconfined", "unconfined", "unconfined_u"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := rm.UserToSELinuxUser(tt.pmlUser)
			if result != tt.expected {
				t.Errorf("UserToSELinuxUser(%s) = %s, want %s", tt.pmlUser, result, tt.expected)
			}
		})
	}
}

func TestGenerateUserRoleMappings(t *testing.T) {
	rm := NewRoleMapper("app")

	relations := []models.RoleRelation{
		{Member: "root", Role: "admin"},
		{Member: "john", Role: "user"},
		{Member: "john", Role: "staff"},
	}

	mappings := rm.GenerateUserRoleMappings(relations)

	if len(mappings) == 0 {
		t.Error("Expected user-role mappings to be generated")
	}

	// Check that we have mappings for both users
	hasRoot := false
	hasJohn := false

	for _, mapping := range mappings {
		// Root could map to "root" user with app_admin_r role
		if strings.Contains(mapping, "user root roles") && strings.Contains(mapping, "admin") {
			hasRoot = true
		}
		// john maps to user_u and should have multiple roles
		if strings.Contains(mapping, "user user_u roles") &&
			(strings.Contains(mapping, "user_r") || strings.Contains(mapping, "app_user_r")) &&
			(strings.Contains(mapping, "staff_r") || strings.Contains(mapping, "app_staff_r")) {
			hasJohn = true
		}
	}

	if !hasRoot {
		t.Errorf("Expected root user mapping, got: %v", mappings)
	}

	if !hasJohn {
		t.Errorf("Expected john user mapping with multiple roles, got: %v", mappings)
	}
}

func TestAddCustomMapping(t *testing.T) {
	rm := NewRoleMapper("app")

	rm.AddCustomMapping("webapp_user", "webapp_r")

	result := rm.MapRole("webapp_user")
	if result != "webapp_r" {
		t.Errorf("Custom mapping failed: got %s, want webapp_r", result)
	}
}

func TestValidateRoleName(t *testing.T) {
	tests := []struct {
		name      string
		roleName  string
		expectErr bool
	}{
		{"Valid role", "user_r", false},
		{"Invalid - no suffix", "user", true},
		{"Invalid - with space", "user r", true},
		{"Valid custom role", "myapp_admin_r", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateRoleName(tt.roleName)
			if (err != nil) != tt.expectErr {
				t.Errorf("ValidateRoleName(%s) error = %v, expectErr %v",
					tt.roleName, err, tt.expectErr)
			}
		})
	}
}
