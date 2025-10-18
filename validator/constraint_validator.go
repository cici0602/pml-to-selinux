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
		// Check for privilege escalation
		if cv.isPrivilegeEscalation(trans.SourceType, trans.NewType) {
			violations = append(violations, ConstraintViolation{
				Type: "privilege_escalation",
				Message: fmt.Sprintf("Transition from %s to %s may be privilege escalation",
					trans.SourceType, trans.NewType),
				Rule: trans,
			})
		}

		// Check for invalid cross-domain transitions
		if cv.isInvalidCrossDomain(trans.SourceType, trans.NewType) {
			violations = append(violations, ConstraintViolation{
				Type: "invalid_cross_domain",
				Message: fmt.Sprintf("Invalid cross-domain transition from %s to %s",
					trans.SourceType, trans.NewType),
				Rule: trans,
			})
		}

		// Check for missing entry point
		if trans.TargetType == "" {
			violations = append(violations, ConstraintViolation{
				Type: "missing_entry_point",
				Message: fmt.Sprintf("Domain transition from %s to %s missing entry point",
					trans.SourceType, trans.NewType),
				Rule: trans,
			})
		}

		// Check for untrusted domain transitions
		if cv.isUntrustedTransition(trans.SourceType, trans.NewType) {
			violations = append(violations, ConstraintViolation{
				Type: "untrusted_transition",
				Message: fmt.Sprintf("Untrusted transition from %s to %s",
					trans.SourceType, trans.NewType),
				Rule: trans,
			})
		}
	}

	return violations
}

// isPrivilegeEscalation checks if a transition represents privilege escalation
func (cv *ConstraintValidator) isPrivilegeEscalation(sourceType, newType string) bool {
	privilegedDomains := []string{"admin", "sysadm", "secadm", "auditadm", "root"}
	unprivilegedDomains := []string{"user", "guest", "app"}

	sourcePrivileged := false
	targetPrivileged := false

	for _, priv := range privilegedDomains {
		if strings.Contains(strings.ToLower(sourceType), priv) {
			sourcePrivileged = true
		}
		if strings.Contains(strings.ToLower(newType), priv) {
			targetPrivileged = true
		}
	}

	for _, unpriv := range unprivilegedDomains {
		if strings.Contains(strings.ToLower(sourceType), unpriv) {
			sourcePrivileged = false
		}
	}

	// Escalation if unprivileged domain transitions to privileged domain
	return !sourcePrivileged && targetPrivileged
}

// isInvalidCrossDomain checks for invalid cross-domain transitions
func (cv *ConstraintValidator) isInvalidCrossDomain(sourceType, newType string) bool {
	// User domains should not transition to system domains without proper authorization
	if strings.Contains(strings.ToLower(sourceType), "user") &&
		strings.Contains(strings.ToLower(newType), "system") {
		return true
	}

	// Guest domains should have minimal transition capabilities
	if strings.Contains(strings.ToLower(sourceType), "guest") &&
		!strings.Contains(strings.ToLower(newType), "guest") {
		return true
	}

	return false
}

// isUntrustedTransition checks if transition involves untrusted domains
func (cv *ConstraintValidator) isUntrustedTransition(sourceType, newType string) bool {
	untrustedMarkers := []string{"untrusted", "tmp", "tmpfs"}

	for _, marker := range untrustedMarkers {
		if strings.Contains(strings.ToLower(sourceType), marker) ||
			strings.Contains(strings.ToLower(newType), marker) {
			return true
		}
	}

	return false
}

// ValidateTransitionPath validates the complete transition path
func (cv *ConstraintValidator) ValidateTransitionPath(
	transitions []models.TypeTransition,
) []error {
	errors := make([]error, 0)

	// Build transition graph
	transGraph := make(map[string][]string)
	for _, trans := range transitions {
		transGraph[trans.SourceType] = append(transGraph[trans.SourceType], trans.NewType)
	}

	// Check for reachability to privileged domains
	for sourceType, targets := range transGraph {
		for _, targetType := range targets {
			// Check if this creates an unauthorized path to privileged domains
			if cv.isUnauthorizedPrivilegedPath(sourceType, targetType, transGraph) {
				errors = append(errors, fmt.Errorf(
					"unauthorized path to privileged domain: %s -> %s",
					sourceType, targetType))
			}
		}
	}

	// Also check for indirect paths (multi-hop transitions)
	for sourceType := range transGraph {
		reachable := cv.getReachableDomains(sourceType, transGraph, make(map[string]bool))
		for _, reachableType := range reachable {
			if cv.isDirectPrivilegeEscalation(sourceType, reachableType) {
				errors = append(errors, fmt.Errorf(
					"indirect unauthorized path: %s can reach %s",
					sourceType, reachableType))
			}
		}
	}

	return errors
}

// getReachableDomains performs BFS to find all reachable domains
func (cv *ConstraintValidator) getReachableDomains(
	start string,
	graph map[string][]string,
	visited map[string]bool,
) []string {
	if visited[start] {
		return []string{}
	}

	visited[start] = true
	reachable := []string{}

	if targets, ok := graph[start]; ok {
		for _, target := range targets {
			reachable = append(reachable, target)
			// Recursively get reachable from this target
			indirectReachable := cv.getReachableDomains(target, graph, visited)
			reachable = append(reachable, indirectReachable...)
		}
	}

	return reachable
}

// isDirectPrivilegeEscalation checks direct privilege escalation without intermediate check
func (cv *ConstraintValidator) isDirectPrivilegeEscalation(source, target string) bool {
	privilegedDomains := []string{"admin", "sysadm", "secadm"}
	unprivilegedDomains := []string{"user", "guest", "app"}

	sourceUnpriv := false
	targetPriv := false

	for _, unpriv := range unprivilegedDomains {
		if strings.Contains(strings.ToLower(source), unpriv) {
			sourceUnpriv = true
			break
		}
	}

	for _, priv := range privilegedDomains {
		if strings.Contains(strings.ToLower(target), priv) {
			targetPriv = true
			break
		}
	}

	return sourceUnpriv && targetPriv
}

// isUnauthorizedPrivilegedPath checks if a transition creates unauthorized access to privileged domains
func (cv *ConstraintValidator) isUnauthorizedPrivilegedPath(
	source, target string,
	graph map[string][]string,
) bool {
	privilegedDomains := []string{"admin", "sysadm", "secadm"}

	// Simple check: if source is unprivileged and can reach privileged domain
	sourceUnpriv := strings.Contains(strings.ToLower(source), "user") ||
		strings.Contains(strings.ToLower(source), "guest")

	if !sourceUnpriv {
		return false
	}

	// Check if target is privileged or leads to privileged
	for _, priv := range privilegedDomains {
		if strings.Contains(strings.ToLower(target), priv) {
			return true
		}
	}

	return false
}
