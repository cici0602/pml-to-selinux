package validator

import (
	"strings"
	"testing"

	"github.com/cici0602/pml-to-selinux/models"
)

// TestConstraintValidator_PrivilegeEscalation tests privilege escalation detection
func TestConstraintValidator_PrivilegeEscalation(t *testing.T) {
	cv := NewConstraintValidator()

	transitions := []models.TypeTransition{
		{
			SourceType: "user_t",
			TargetType: "bash_exec_t",
			NewType:    "sysadm_t", // Privilege escalation
			Class:      "process",
		},
		{
			SourceType: "app_t",
			TargetType: "bin_t",
			NewType:    "admin_t", // Privilege escalation
			Class:      "process",
		},
		{
			SourceType: "admin_t",
			TargetType: "bin_t",
			NewType:    "sysadm_t", // Valid - already privileged
			Class:      "process",
		},
		{
			SourceType: "user_t",
			TargetType: "app_exec_t",
			NewType:    "user_app_t", // Normal transition
			Class:      "process",
		},
	}

	violations := cv.CheckDomainTransitionConstraints(transitions)

	// Should detect at least 2 privilege escalations
	if len(violations) < 2 {
		t.Errorf("Expected at least 2 violations, got %d", len(violations))
	}

	// Check that violations are properly categorized
	escalationCount := 0
	for _, v := range violations {
		if v.Type == "privilege_escalation" {
			escalationCount++
		}
	}

	if escalationCount < 2 {
		t.Errorf("Expected at least 2 privilege_escalation violations, got %d", escalationCount)
	}
}

// TestConstraintValidator_CrossDomainTransitions tests cross-domain transition validation
func TestConstraintValidator_CrossDomainTransitions(t *testing.T) {
	cv := NewConstraintValidator()

	transitions := []models.TypeTransition{
		{
			SourceType: "user_t",
			TargetType: "system_bin_t",
			NewType:    "system_t", // Invalid cross-domain
			Class:      "process",
		},
		{
			SourceType: "guest_t",
			TargetType: "app_exec_t",
			NewType:    "app_t", // Invalid - guest escaping
			Class:      "process",
		},
		{
			SourceType: "system_t",
			TargetType: "helper_exec_t",
			NewType:    "system_helper_t", // Valid - same domain family
			Class:      "process",
		},
	}

	violations := cv.CheckDomainTransitionConstraints(transitions)

	// Should detect invalid cross-domain transitions
	crossDomainCount := 0
	for _, v := range violations {
		if v.Type == "invalid_cross_domain" {
			crossDomainCount++
		}
	}

	if crossDomainCount == 0 {
		t.Error("Expected to detect invalid cross-domain transitions")
	}
}

// TestConstraintValidator_MissingEntryPoint tests missing entry point detection
func TestConstraintValidator_MissingEntryPoint(t *testing.T) {
	cv := NewConstraintValidator()

	transitions := []models.TypeTransition{
		{
			SourceType: "user_t",
			TargetType: "", // Missing entry point
			NewType:    "user_app_t",
			Class:      "process",
		},
	}

	violations := cv.CheckDomainTransitionConstraints(transitions)

	// Should detect missing entry point
	found := false
	for _, v := range violations {
		if v.Type == "missing_entry_point" {
			found = true
			break
		}
	}

	if !found {
		t.Error("Expected to detect missing entry point")
	}
}

// TestConstraintValidator_UntrustedTransitions tests untrusted domain transitions
func TestConstraintValidator_UntrustedTransitions(t *testing.T) {
	cv := NewConstraintValidator()

	transitions := []models.TypeTransition{
		{
			SourceType: "untrusted_t",
			TargetType: "bin_t",
			NewType:    "app_t",
			Class:      "process",
		},
		{
			SourceType: "app_t",
			TargetType: "tmp_exec_t",
			NewType:    "tmp_t",
			Class:      "process",
		},
	}

	violations := cv.CheckDomainTransitionConstraints(transitions)

	// Should detect untrusted transitions
	untrustedCount := 0
	for _, v := range violations {
		if v.Type == "untrusted_transition" {
			untrustedCount++
		}
	}

	if untrustedCount == 0 {
		t.Error("Expected to detect untrusted transitions")
	}
}

// TestConstraintValidator_ValidateTransitionPath tests transition path validation
func TestConstraintValidator_ValidateTransitionPath(t *testing.T) {
	cv := NewConstraintValidator()

	tests := []struct {
		name         string
		transitions  []models.TypeTransition
		expectErrors bool
	}{
		{
			name: "unauthorized path to admin",
			transitions: []models.TypeTransition{
				{
					SourceType: "user_t",
					TargetType: "helper_exec_t",
					NewType:    "helper_t",
					Class:      "process",
				},
				{
					SourceType: "helper_t",
					TargetType: "admin_exec_t",
					NewType:    "admin_t",
					Class:      "process",
				},
			},
			expectErrors: true,
		},
		{
			name: "valid system transition",
			transitions: []models.TypeTransition{
				{
					SourceType: "system_t",
					TargetType: "daemon_exec_t",
					NewType:    "daemon_t",
					Class:      "process",
				},
			},
			expectErrors: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errors := cv.ValidateTransitionPath(tt.transitions)

			if tt.expectErrors && len(errors) == 0 {
				t.Error("Expected errors but got none")
			}

			if !tt.expectErrors && len(errors) > 0 {
				t.Errorf("Unexpected errors: %v", errors)
			}
		})
	}
}

// TestConstraintValidator_ComplexTransitionChain tests complex transition chains
func TestConstraintValidator_ComplexTransitionChain(t *testing.T) {
	cv := NewConstraintValidator()

	// Build a complex transition chain
	transitions := []models.TypeTransition{
		{
			SourceType: "init_t",
			TargetType: "daemon_exec_t",
			NewType:    "daemon_t",
			Class:      "process",
		},
		{
			SourceType: "daemon_t",
			TargetType: "helper_exec_t",
			NewType:    "helper_t",
			Class:      "process",
		},
		{
			SourceType: "helper_t",
			TargetType: "worker_exec_t",
			NewType:    "worker_t",
			Class:      "process",
		},
	}

	violations := cv.CheckDomainTransitionConstraints(transitions)

	// These should be valid system transitions
	for _, v := range violations {
		if v.Type == "privilege_escalation" || v.Type == "invalid_cross_domain" {
			t.Errorf("Unexpected violation in valid system transition chain: %v", v)
		}
	}
}

// TestConstraintValidator_GuestDomainRestrictions tests guest domain restrictions
func TestConstraintValidator_GuestDomainRestrictions(t *testing.T) {
	cv := NewConstraintValidator()

	transitions := []models.TypeTransition{
		{
			SourceType: "guest_t",
			TargetType: "app_exec_t",
			NewType:    "app_t", // Guest trying to escape
			Class:      "process",
		},
		{
			SourceType: "guest_t",
			TargetType: "guest_app_exec_t",
			NewType:    "guest_app_t", // Valid guest transition
			Class:      "process",
		},
	}

	violations := cv.CheckDomainTransitionConstraints(transitions)

	// Should detect invalid guest escape
	foundInvalidEscape := false
	for _, v := range violations {
		if v.Type == "invalid_cross_domain" {
			trans := v.Rule.(models.TypeTransition)
			if trans.SourceType == "guest_t" && trans.NewType == "app_t" {
				foundInvalidEscape = true
				break
			}
		}
	}

	if !foundInvalidEscape {
		t.Error("Expected to detect guest domain escape attempt")
	}
}

// TestConstraintValidator_ViolationMessages tests violation message quality
func TestConstraintValidator_ViolationMessages(t *testing.T) {
	cv := NewConstraintValidator()

	transitions := []models.TypeTransition{
		{
			SourceType: "user_t",
			TargetType: "admin_exec_t",
			NewType:    "admin_t",
			Class:      "process",
		},
	}

	violations := cv.CheckDomainTransitionConstraints(transitions)

	if len(violations) == 0 {
		t.Fatal("Expected violations")
	}

	// Check that violation messages are informative
	for _, v := range violations {
		if v.Message == "" {
			t.Error("Violation message should not be empty")
		}

		if !strings.Contains(v.Message, "user_t") ||
			!strings.Contains(v.Message, "admin_t") {
			t.Errorf("Violation message should contain domain names: %s", v.Message)
		}

		if v.Type == "" {
			t.Error("Violation type should not be empty")
		}
	}
}

// TestConstraintValidator_MultipleViolationTypes tests detection of multiple violation types
func TestConstraintValidator_MultipleViolationTypes(t *testing.T) {
	cv := NewConstraintValidator()

	transitions := []models.TypeTransition{
		{
			SourceType: "user_t",
			TargetType: "",        // Missing entry point
			NewType:    "admin_t", // AND privilege escalation
			Class:      "process",
		},
	}

	violations := cv.CheckDomainTransitionConstraints(transitions)

	// Should detect multiple types of violations
	violationTypes := make(map[string]bool)
	for _, v := range violations {
		violationTypes[v.Type] = true
	}

	expectedTypes := []string{"privilege_escalation", "missing_entry_point"}
	for _, expectedType := range expectedTypes {
		if !violationTypes[expectedType] {
			t.Errorf("Expected violation type %s not found", expectedType)
		}
	}
}
