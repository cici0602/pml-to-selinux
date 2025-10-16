package mapping

import (
	"fmt"
	"strings"

	"github.com/cici0602/pml-to-selinux/models"
)

// RoleMapper handles conversion from PML roles/groups to SELinux roles
type RoleMapper struct {
	// Module name prefix
	modulePrefix string

	// Custom role mappings (PML role -> SELinux role)
	customMappings map[string]string

	// Role hierarchy cache (child -> parents)
	roleHierarchy map[string][]string

	// Default SELinux roles
	defaultRoles map[string]string
}

// NewRoleMapper creates a new RoleMapper instance
func NewRoleMapper(modulePrefix string) *RoleMapper {
	rm := &RoleMapper{
		modulePrefix:   modulePrefix,
		customMappings: make(map[string]string),
		roleHierarchy:  make(map[string][]string),
		defaultRoles:   getDefaultRoles(),
	}
	return rm
}

// getDefaultRoles returns common SELinux role mappings
func getDefaultRoles() map[string]string {
	return map[string]string{
		"user":     "user_r",
		"staff":    "staff_r",
		"sysadm":   "sysadm_r",
		"secadm":   "secadm_r",
		"auditadm": "auditadm_r",
		"system":   "system_r",
		"object":   "object_r",
	}
}

// AddCustomMapping adds a custom PML role to SELinux role mapping
func (rm *RoleMapper) AddCustomMapping(pmlRole, selinuxRole string) {
	rm.customMappings[pmlRole] = selinuxRole
}

// MapRole converts a PML role/group to SELinux role
func (rm *RoleMapper) MapRole(pmlRole string) string {
	// Check custom mapping first
	if seRole, ok := rm.customMappings[pmlRole]; ok {
		return seRole
	}

	// Check default roles
	roleLower := strings.ToLower(pmlRole)
	if seRole, ok := rm.defaultRoles[roleLower]; ok {
		return seRole
	}

	// Generate role name from PML role
	return rm.generateRoleName(pmlRole)
}

// generateRoleName generates a SELinux role name from PML role
func (rm *RoleMapper) generateRoleName(pmlRole string) string {
	// Sanitize the role name
	roleName := strings.ToLower(pmlRole)
	roleName = strings.ReplaceAll(roleName, "-", "_")
	roleName = strings.ReplaceAll(roleName, " ", "_")

	// Remove common suffixes
	roleName = strings.TrimSuffix(roleName, "_role")
	roleName = strings.TrimSuffix(roleName, "_group")

	// Add module prefix if provided
	if rm.modulePrefix != "" && !strings.HasPrefix(roleName, rm.modulePrefix+"_") {
		roleName = rm.modulePrefix + "_" + roleName
	}

	// Ensure it ends with _r
	if !strings.HasSuffix(roleName, "_r") {
		roleName = roleName + "_r"
	}

	return roleName
}

// BuildRoleHierarchy builds role hierarchy from PML role relations
func (rm *RoleMapper) BuildRoleHierarchy(relations []models.RoleRelation) {
	for _, rel := range relations {
		// rel.Member is a member of rel.Role
		// Store as: member -> parent roles
		rm.roleHierarchy[rel.Member] = append(rm.roleHierarchy[rel.Member], rel.Role)
	}
}

// GetRoleParents returns all parent roles for a given role
func (rm *RoleMapper) GetRoleParents(role string) []string {
	parents := []string{}
	if parentRoles, ok := rm.roleHierarchy[role]; ok {
		for _, parent := range parentRoles {
			parents = append(parents, rm.MapRole(parent))
			// Recursively get parents of parents
			grandParents := rm.GetRoleParents(parent)
			parents = append(parents, grandParents...)
		}
	}
	return removeDuplicates(parents)
}

// GenerateRoleAllowRules generates SELinux role allow rules from role hierarchy
// Returns a list of "allow role1 role2;" statements
func (rm *RoleMapper) GenerateRoleAllowRules() []string {
	rules := []string{}

	for child, parents := range rm.roleHierarchy {
		childRole := rm.MapRole(child)
		for _, parent := range parents {
			parentRole := rm.MapRole(parent)
			rule := fmt.Sprintf("allow %s %s;", childRole, parentRole)
			rules = append(rules, rule)
		}
	}

	return removeDuplicates(rules)
}

// GenerateRoleDomainAssociations generates role-type associations
// This maps which domains (types) can be entered by which roles
func (rm *RoleMapper) GenerateRoleDomainAssociations(domains []string) []RoleDomainAssoc {
	assocs := []RoleDomainAssoc{}

	for _, domain := range domains {
		// Infer role from domain name
		role := rm.InferRoleFromDomain(domain)
		assocs = append(assocs, RoleDomainAssoc{
			Role:   role,
			Domain: domain,
		})
	}

	return assocs
}

// InferRoleFromDomain infers which role should be associated with a domain
func (rm *RoleMapper) InferRoleFromDomain(domain string) string {
	domainLower := strings.ToLower(domain)

	// System processes
	if strings.Contains(domainLower, "system") || strings.Contains(domainLower, "kernel") {
		return "system_r"
	}

	// User processes
	if strings.Contains(domainLower, "user") {
		return "user_r"
	}

	// Administrative processes
	if strings.Contains(domainLower, "admin") || strings.Contains(domainLower, "sysadm") {
		return "sysadm_r"
	}

	// Web servers and daemons typically run as system_r
	if strings.HasSuffix(domainLower, "_t") || strings.HasSuffix(domainLower, "_d") {
		return "system_r"
	}

	// Default to system_r for daemons
	return "system_r"
}

// RoleDomainAssoc represents a role-domain association
type RoleDomainAssoc struct {
	Role   string // SELinux role
	Domain string // SELinux domain (type)
}

// GenerateRoleTransitionRules generates role_transition rules
// Format: role_transition source_role target_type : process new_role;
func (rm *RoleMapper) GenerateRoleTransitionRules(transitions []models.Transition) []string {
	rules := []string{}

	for _, trans := range transitions {
		// Infer roles from domain types
		sourceRole := rm.InferRoleFromDomain(trans.SourceType)
		newRole := rm.InferRoleFromDomain(trans.NewType)

		if sourceRole != newRole {
			rule := fmt.Sprintf("role_transition %s %s:process %s;",
				sourceRole, trans.TargetType, newRole)
			rules = append(rules, rule)
		}
	}

	return removeDuplicates(rules)
}

// UserToSELinuxUser converts a PML user to SELinux user
func (rm *RoleMapper) UserToSELinuxUser(pmlUser string) string {
	userLower := strings.ToLower(pmlUser)

	// Check for common patterns
	if userLower == "root" || userLower == "admin" {
		return "root"
	}

	if strings.Contains(userLower, "system") {
		return "system_u"
	}

	if userLower == "unconfined" {
		return "unconfined_u"
	}

	// Default to user_u
	return "user_u"
}

// GenerateUserRoleMapping generates SELinux user-role mappings
// Format: user user_u roles { user_r };
func (rm *RoleMapper) GenerateUserRoleMappings(roles []models.RoleRelation) []string {
	// Group roles by user
	userRoles := make(map[string][]string)

	for _, rel := range roles {
		user := rm.UserToSELinuxUser(rel.Member)
		role := rm.MapRole(rel.Role)
		userRoles[user] = append(userRoles[user], role)
	}

	// Generate mappings
	mappings := []string{}
	for user, roles := range userRoles {
		uniqueRoles := removeDuplicates(roles)
		rolesStr := strings.Join(uniqueRoles, " ")
		mapping := fmt.Sprintf("user %s roles { %s };", user, rolesStr)
		mappings = append(mappings, mapping)
	}

	return mappings
}

// removeDuplicates removes duplicate strings from a slice
func removeDuplicates(slice []string) []string {
	seen := make(map[string]bool)
	result := []string{}

	for _, item := range slice {
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}

	return result
}

// ValidateRoleName validates if a role name follows SELinux naming conventions
func ValidateRoleName(roleName string) error {
	if !strings.HasSuffix(roleName, "_r") {
		return fmt.Errorf("role name must end with _r: %s", roleName)
	}

	if strings.Contains(roleName, " ") {
		return fmt.Errorf("role name cannot contain spaces: %s", roleName)
	}

	return nil
}
