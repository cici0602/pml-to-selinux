package mapping

import (
	"strings"
	"testing"

	"github.com/cici0602/pml-to-selinux/models"
)

// TestRoleMapper_ValidateUserRoleAssignment tests user-role assignment validation
func TestRoleMapper_ValidateUserRoleAssignment(t *testing.T) {
	rm := NewRoleMapper("app")

	tests := []struct {
		name        string
		user        string
		role        string
		shouldError bool
	}{
		{
			name:        "valid user role",
			user:        "john",
			role:        "user_r",
			shouldError: false,
		},
		{
			name:        "valid admin role",
			user:        "admin",
			role:        "sysadm_r",
			shouldError: false,
		},
		{
			name:        "invalid - regular user trying admin role",
			user:        "john",
			role:        "sysadm_r",
			shouldError: true,
		},
		{
			name:        "invalid - role name without _r suffix",
			user:        "john",
			role:        "user",
			shouldError: true,
		},
		{
			name:        "valid root user admin role",
			user:        "root",
			role:        "secadm_r",
			shouldError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := rm.ValidateUserRoleAssignment(tt.user, tt.role)
			if tt.shouldError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.shouldError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

// TestRoleMapper_CheckRoleConsistency tests role hierarchy consistency
func TestRoleMapper_CheckRoleConsistency(t *testing.T) {
	tests := []struct {
		name          string
		relations     []models.RoleRelation
		expectErrors  bool
		errorContains string
	}{
		{
			name: "valid hierarchy",
			relations: []models.RoleRelation{
				{Member: "user", Role: "staff"},
				{Member: "staff", Role: "sysadm"},
			},
			expectErrors: false,
		},
		{
			name: "circular dependency",
			relations: []models.RoleRelation{
				{Member: "role_a", Role: "role_b"},
				{Member: "role_b", Role: "role_c"},
				{Member: "role_c", Role: "role_a"},
			},
			expectErrors:  true,
			errorContains: "circular dependency",
		},
		{
			name: "self-reference",
			relations: []models.RoleRelation{
				{Member: "role_a", Role: "role_a"},
			},
			expectErrors:  true,
			errorContains: "circular dependency",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rm := NewRoleMapper("test")
			rm.BuildRoleHierarchy(tt.relations)
			errors := rm.CheckRoleConsistency()

			if tt.expectErrors && len(errors) == 0 {
				t.Error("Expected errors but got none")
			}

			if !tt.expectErrors && len(errors) > 0 {
				t.Errorf("Unexpected errors: %v", errors)
			}

			if tt.expectErrors && tt.errorContains != "" {
				found := false
				for _, err := range errors {
					if strings.Contains(err.Error(), tt.errorContains) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected error containing %q, got: %v", tt.errorContains, errors)
				}
			}
		})
	}
}

// TestRoleMapper_GenerateRoleConstraints tests constraint generation
func TestRoleMapper_GenerateRoleConstraints(t *testing.T) {
	rm := NewRoleMapper("app")

	constraints := rm.GenerateRoleConstraints()

	if len(constraints) == 0 {
		t.Error("Expected constraints to be generated")
	}

	// Check for key constraints
	hasRoleTransitionConstraint := false
	hasPrivEscalationConstraint := false

	for _, constraint := range constraints {
		if strings.Contains(constraint, "r1 == r2 or t1 == can_change_role") {
			hasRoleTransitionConstraint = true
		}
		if strings.Contains(constraint, "sysadm_r") {
			hasPrivEscalationConstraint = true
		}
	}

	if !hasRoleTransitionConstraint {
		t.Error("Missing role transition constraint")
	}

	if !hasPrivEscalationConstraint {
		t.Error("Missing privilege escalation constraint")
	}
}

// TestValidateRoleName_DetailedChecks tests detailed role name validation
func TestValidateRoleName_DetailedChecks(t *testing.T) {
	tests := []struct {
		name        string
		roleName    string
		shouldError bool
		errorMsg    string
	}{
		{
			name:        "valid role name",
			roleName:    "user_r",
			shouldError: false,
		},
		{
			name:        "valid complex name",
			roleName:    "webapp_admin_r",
			shouldError: false,
		},
		{
			name:        "missing _r suffix",
			roleName:    "user",
			shouldError: true,
			errorMsg:    "must end with _r",
		},
		{
			name:        "contains spaces",
			roleName:    "user role_r",
			shouldError: true,
			errorMsg:    "cannot contain spaces",
		},
		{
			name:        "invalid character - dash",
			roleName:    "user-role_r",
			shouldError: true,
			errorMsg:    "invalid character",
		},
		{
			name:        "invalid character - dot",
			roleName:    "user.role_r",
			shouldError: true,
			errorMsg:    "invalid character",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateRoleName(tt.roleName)

			if tt.shouldError {
				if err == nil {
					t.Error("Expected error but got none")
				} else if tt.errorMsg != "" && !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("Expected error containing %q, got: %v", tt.errorMsg, err)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}

// TestRoleMapper_ComplexHierarchy tests complex role hierarchies
func TestRoleMapper_ComplexHierarchy(t *testing.T) {
	rm := NewRoleMapper("app")

	// Build a complex hierarchy
	relations := []models.RoleRelation{
		{Member: "intern", Role: "user"},
		{Member: "user", Role: "staff"},
		{Member: "staff", Role: "senior"},
		{Member: "senior", Role: "lead"},
		{Member: "lead", Role: "admin"},
	}

	rm.BuildRoleHierarchy(relations)

	// Check that intern inherits all parent roles
	parents := rm.GetRoleParents("intern")

	// Should have at least 4 parent roles
	if len(parents) < 4 {
		t.Errorf("Expected at least 4 parent roles for intern, got %d", len(parents))
	}

	// Check for admin in the hierarchy
	hasAdmin := false
	for _, p := range parents {
		if strings.Contains(p, "admin") {
			hasAdmin = true
			break
		}
	}

	if !hasAdmin {
		t.Error("Expected intern to inherit admin role through hierarchy")
	}
}

// TestRoleMapper_RoleTransitionRules tests role transition rule generation
func TestRoleMapper_RoleTransitionRules(t *testing.T) {
	rm := NewRoleMapper("app")

	transitions := []models.TransitionInfo{
		{
			SourceType: "user_t",
			TargetType: "bin_t",
			NewType:    "admin_t",
		},
		{
			SourceType: "system_t",
			TargetType: "lib_t",
			NewType:    "system_helper_t",
		},
	}

	rules := rm.GenerateRoleTransitionRules(transitions)

	if len(rules) == 0 {
		t.Error("Expected role transition rules to be generated")
	}

	// Check that rules contain expected elements
	for _, rule := range rules {
		if !strings.Contains(rule, "role_transition") {
			t.Errorf("Rule should contain 'role_transition': %s", rule)
		}
		if !strings.Contains(rule, ":process") {
			t.Errorf("Rule should specify process class: %s", rule)
		}
	}
}

// TestRoleMapper_UserRoleMappingWithConstraints tests user-role mappings with constraints
func TestRoleMapper_UserRoleMappingWithConstraints(t *testing.T) {
	rm := NewRoleMapper("app")

	relations := []models.RoleRelation{
		{Member: "root", Role: "admin"},
		{Member: "root", Role: "secadm"},
		{Member: "john", Role: "user"},
	}

	// Validate each assignment
	for _, rel := range relations {
		err := rm.ValidateUserRoleAssignment(rel.Member, rm.MapRole(rel.Role))
		if err != nil {
			// root should be able to have admin roles
			if rel.Member == "root" && (rel.Role == "admin" || rel.Role == "secadm") {
				t.Errorf("root should be allowed admin roles: %v", err)
			}
		}
	}

	// Generate mappings
	mappings := rm.GenerateUserRoleMappings(relations)

	if len(mappings) == 0 {
		t.Error("Expected user-role mappings to be generated")
	}
}
