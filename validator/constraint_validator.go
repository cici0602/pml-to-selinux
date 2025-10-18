package validator

import (
	"fmt"
	"strings"

	"github.com/cici0602/pml-to-selinux/models"
)

// ConstraintValidator validates SELinux policy constraints
type ConstraintValidator struct {
	// User-role mappings
	userRoles map[string][]string

	// Role-type mappings (which types can be associated with which roles)
	roleTypes map[string][]string

	// Valid role transitions
	roleTransitions map[string][]string // fromRole -> []toRole
}

// NewConstraintValidator creates a new constraint validator
func NewConstraintValidator() *ConstraintValidator {
	return &ConstraintValidator{
		userRoles:       make(map[string][]string),
		roleTypes:       make(map[string][]string),
		roleTransitions: make(map[string][]string),
	}
}

// AddUserRoleMapping adds a valid user-role mapping
func (cv *ConstraintValidator) AddUserRoleMapping(user, role string) {
	cv.userRoles[user] = append(cv.userRoles[user], role)
}

// AddRoleTypeMapping adds a valid role-type mapping
func (cv *ConstraintValidator) AddRoleTypeMapping(role, typeStr string) {
	cv.roleTypes[role] = append(cv.roleTypes[role], typeStr)
}

// AddRoleTransition adds a valid role transition
func (cv *ConstraintValidator) AddRoleTransition(fromRole, toRole string) {
	cv.roleTransitions[fromRole] = append(cv.roleTransitions[fromRole], toRole)
}

// ValidateUserRole checks if a user can have a specific role
func (cv *ConstraintValidator) ValidateUserRole(user, role string) error {
	roles, ok := cv.userRoles[user]
	if !ok {
		return fmt.Errorf("user %s has no role mappings", user)
	}

	for _, r := range roles {
		if r == role {
			return nil
		}
	}

	return fmt.Errorf("user %s is not allowed role %s (allowed: %v)",
		user, role, roles)
}

// ValidateRoleType checks if a role can be associated with a type
func (cv *ConstraintValidator) ValidateRoleType(role, typeStr string) error {
	types, ok := cv.roleTypes[role]
	if !ok {
		// If no explicit mapping, allow by default (permissive)
		return nil
	}

	for _, t := range types {
		if t == typeStr {
			return nil
		}
	}

	return fmt.Errorf("role %s cannot be associated with type %s (allowed: %v)",
		role, typeStr, types)
}

// ValidateRoleTransition checks if a role transition is valid
func (cv *ConstraintValidator) ValidateRoleTransition(fromRole, toRole string) error {
	validTargets, ok := cv.roleTransitions[fromRole]
	if !ok {
		// If no transitions defined, deny by default (restrictive)
		return fmt.Errorf("no transitions defined from role %s", fromRole)
	}

	for _, target := range validTargets {
		if target == toRole {
			return nil
		}
	}

	return fmt.Errorf("transition from %s to %s not allowed (allowed: %v)",
		fromRole, toRole, validTargets)
}

// GenerateConstraints generates SELinux constraint rules from the validator configuration
func (cv *ConstraintValidator) GenerateConstraints() []models.Constraint {
	constraints := make([]models.Constraint, 0)

	// Generate user-role constraints
	// constrain process transition ( u1 == u2 or t1 == can_change_user );
	userRoleConstraint := models.Constraint{
		Type:        "constrain",
		Classes:     []string{"process"},
		Permissions: []string{"transition"},
		Expression:  "u1 == u2 or t1 == can_change_user",
	}
	constraints = append(constraints, userRoleConstraint)

	// Generate role-type constraints
	// constrain process transition ( r1 == r2 or t1 == can_change_role );
	roleTypeConstraint := models.Constraint{
		Type:        "constrain",
		Classes:     []string{"process"},
		Permissions: []string{"transition"},
		Expression:  "r1 == r2 or t1 == can_change_role",
	}
	constraints = append(constraints, roleTypeConstraint)

	return constraints
}

// ValidatePolicy validates all constraints in a policy
func (cv *ConstraintValidator) ValidatePolicy(policy *models.SELinuxPolicy) []error {
	errors := make([]error, 0)

	// Validate all type transitions
	for _, trans := range policy.Transitions {
		// Check if source and target types are compatible
		if trans.SourceType != "" && trans.NewType != "" {
			// Could add more sophisticated validation here
		}
	}

	// Validate file contexts
	for _, fc := range policy.FileContexts {
		// Validate that the role is valid
		if fc.Role != "" && fc.Role != "object_r" && fc.Role != "system_r" {
			// Check if it's a known role
			found := false
			for _, roles := range cv.userRoles {
				for _, r := range roles {
					if strings.HasSuffix(r, "_r") && fc.Role == r {
						found = true
						break
					}
				}
				if found {
					break
				}
			}
			if !found {
				errors = append(errors, fmt.Errorf(
					"file context %s uses unknown role %s", fc.PathPattern, fc.Role))
			}
		}
	}

	return errors
}

// ConstraintViolation represents a constraint violation
type ConstraintViolation struct {
	Type    string
	Message string
	Rule    interface{} // The rule that violates the constraint
}

// CheckDomainTransitionConstraints checks if domain transitions follow constraints
func (cv *ConstraintValidator) CheckDomainTransitionConstraints(
	transitions []models.TypeTransition,
) []ConstraintViolation {
	violations := make([]ConstraintViolation, 0)

	// Check each transition for potential issues
	for _, trans := range transitions {
		// Example: check if transition is to a more privileged domain
		// This is a simplified check - real implementation would be more sophisticated
		if strings.Contains(trans.NewType, "admin") &&
			!strings.Contains(trans.SourceType, "admin") {
			violations = append(violations, ConstraintViolation{
				Type: "privilege_escalation",
				Message: fmt.Sprintf("Transition from %s to %s may be privilege escalation",
					trans.SourceType, trans.NewType),
				Rule: trans,
			})
		}
	}

	return violations
}
