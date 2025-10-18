package validator

import (
	"testing"

	"github.com/cici0602/pml-to-selinux/models"
)

func TestConstraintValidator_UserRole(t *testing.T) {
	cv := NewConstraintValidator()

	// Add some user-role mappings
	cv.AddUserRoleMapping("root", "sysadm_r")
	cv.AddUserRoleMapping("root", "system_r")
	cv.AddUserRoleMapping("user", "user_r")

	tests := []struct {
		name    string
		user    string
		role    string
		wantErr bool
	}{
		{
			name:    "valid root sysadm",
			user:    "root",
			role:    "sysadm_r",
			wantErr: false,
		},
		{
			name:    "valid root system",
			user:    "root",
			role:    "system_r",
			wantErr: false,
		},
		{
			name:    "valid user role",
			user:    "user",
			role:    "user_r",
			wantErr: false,
		},
		{
			name:    "invalid root user_r",
			user:    "root",
			role:    "user_r",
			wantErr: true,
		},
		{
			name:    "invalid user sysadm_r",
			user:    "user",
			role:    "sysadm_r",
			wantErr: true,
		},
		{
			name:    "unknown user",
			user:    "unknown",
			role:    "any_r",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := cv.ValidateUserRole(tt.user, tt.role)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateUserRole() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestConstraintValidator_RoleType(t *testing.T) {
	cv := NewConstraintValidator()

	// Add some role-type mappings
	cv.AddRoleTypeMapping("sysadm_r", "sysadm_t")
	cv.AddRoleTypeMapping("user_r", "user_t")
	cv.AddRoleTypeMapping("user_r", "user_home_t")

	tests := []struct {
		name    string
		role    string
		typeStr string
		wantErr bool
	}{
		{
			name:    "valid sysadm type",
			role:    "sysadm_r",
			typeStr: "sysadm_t",
			wantErr: false,
		},
		{
			name:    "valid user type",
			role:    "user_r",
			typeStr: "user_t",
			wantErr: false,
		},
		{
			name:    "valid user home type",
			role:    "user_r",
			typeStr: "user_home_t",
			wantErr: false,
		},
		{
			name:    "invalid sysadm with user_t",
			role:    "sysadm_r",
			typeStr: "user_t",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := cv.ValidateRoleType(tt.role, tt.typeStr)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateRoleType() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestConstraintValidator_RoleTransition(t *testing.T) {
	cv := NewConstraintValidator()

	// Add some role transitions
	cv.AddRoleTransition("system_r", "sysadm_r")
	cv.AddRoleTransition("sysadm_r", "user_r")
	cv.AddRoleTransition("user_r", "user_r") // self-transition

	tests := []struct {
		name     string
		fromRole string
		toRole   string
		wantErr  bool
	}{
		{
			name:     "valid system to sysadm",
			fromRole: "system_r",
			toRole:   "sysadm_r",
			wantErr:  false,
		},
		{
			name:     "valid sysadm to user",
			fromRole: "sysadm_r",
			toRole:   "user_r",
			wantErr:  false,
		},
		{
			name:     "valid self-transition",
			fromRole: "user_r",
			toRole:   "user_r",
			wantErr:  false,
		},
		{
			name:     "invalid user to sysadm",
			fromRole: "user_r",
			toRole:   "sysadm_r",
			wantErr:  true,
		},
		{
			name:     "no transitions defined",
			fromRole: "unknown_r",
			toRole:   "any_r",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := cv.ValidateRoleTransition(tt.fromRole, tt.toRole)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateRoleTransition() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestConstraintValidator_GenerateConstraints(t *testing.T) {
	cv := NewConstraintValidator()

	constraints := cv.GenerateConstraints()

	if len(constraints) == 0 {
		t.Error("GenerateConstraints() returned empty list")
	}

	// Check that at least one constraint is for process transition
	foundProcessTransition := false
	for _, c := range constraints {
		if c.Type == "constrain" && len(c.Classes) > 0 && c.Classes[0] == "process" {
			foundProcessTransition = true
			break
		}
	}

	if !foundProcessTransition {
		t.Error("GenerateConstraints() did not generate process transition constraint")
	}
}

func TestConstraintValidator_ValidatePolicy(t *testing.T) {
	cv := NewConstraintValidator()
	cv.AddUserRoleMapping("system", "system_r")

	policy := models.NewSELinuxPolicy("test", "1.0")

	// Add some file contexts
	policy.AddFileContext(models.FileContext{
		PathPattern: "/test",
		FileType:    "test_t",
		Role:        "system_r",
	})

	// Add an invalid role
	policy.AddFileContext(models.FileContext{
		PathPattern: "/invalid",
		FileType:    "test_t",
		Role:        "unknown_r",
	})

	errors := cv.ValidatePolicy(policy)

	// Should have at least one error (the unknown role)
	if len(errors) == 0 {
		t.Error("ValidatePolicy() did not detect invalid role")
	}
}

func TestConstraintValidator_CheckDomainTransitionConstraints(t *testing.T) {
	cv := NewConstraintValidator()

	transitions := []models.TypeTransition{
		{
			SourceType: "user_t",
			TargetType: "file_t",
			Class:      "process",
			NewType:    "admin_t", // Privilege escalation
		},
		{
			SourceType: "user_t",
			TargetType: "file_t",
			Class:      "process",
			NewType:    "user_app_t", // Normal transition
		},
	}

	violations := cv.CheckDomainTransitionConstraints(transitions)

	// Should detect at least the privilege escalation
	if len(violations) == 0 {
		t.Error("CheckDomainTransitionConstraints() did not detect potential privilege escalation")
	}

	// Check that it found the right violation
	foundEscalation := false
	for _, v := range violations {
		if v.Type == "privilege_escalation" {
			foundEscalation = true
			break
		}
	}

	if !foundEscalation {
		t.Error("CheckDomainTransitionConstraints() did not identify privilege_escalation type")
	}
}
