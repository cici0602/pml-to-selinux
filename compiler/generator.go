package compiler

import (
	"fmt"
	"strings"

	"github.com/cici0602/pml-to-selinux/mapping"
	"github.com/cici0602/pml-to-selinux/models"
)

// Generator orchestrates the conversion from PML to SELinux policy
type Generator struct {
	decoded      *models.DecodedPML
	moduleName   string
	typeMapper   *mapping.TypeMapper
	pathMapper   *mapping.PathMapper
	actionMapper *mapping.ActionMapper
}

// NewGenerator creates a new Generator instance from decoded PML
func NewGenerator(decoded *models.DecodedPML, moduleName string) *Generator {
	return &Generator{
		decoded:      decoded,
		moduleName:   moduleName,
		typeMapper:   mapping.NewTypeMapper(moduleName),
		pathMapper:   mapping.NewPathMapper(),
		actionMapper: mapping.NewActionMapper(),
	}
}

// Generate converts decoded PML to SELinux policy
func (g *Generator) Generate() (*models.SELinuxPolicy, error) {
	if g.decoded == nil {
		return nil, fmt.Errorf("decoded PML cannot be nil")
	}

	// Infer module name if not provided
	moduleName := g.moduleName
	if moduleName == "" {
		moduleName = g.inferModuleName()
	}

	policy := &models.SELinuxPolicy{
		ModuleName: moduleName,
		Version:    "1.0.0",
		Types:      make([]models.TypeDeclaration, 0),
		Rules:      make([]models.AllowRule, 0),
		// DenyRules removed - not supported in simplified version
		Transitions:  make([]models.TypeTransition, 0),
		FileContexts: make([]models.FileContext, 0),
		Capabilities: make([]models.CapabilityRule, 0),
		PortBindings: make([]models.PortBinding, 0),
	}

	// Extract types from subjects and objects
	typeMap := g.extractTypes()
	for typeName, attrs := range typeMap {
		policy.Types = append(policy.Types, models.TypeDeclaration{
			TypeName:   typeName,
			Attributes: attrs,
		})
	}

	// Convert policies to SELinux rules
	if err := g.convertPolicies(policy); err != nil {
		return nil, err
	}

	// Convert transitions
	if err := g.convertTransitions(policy); err != nil {
		return nil, err
	}

	// Generate file contexts from object paths
	if err := g.generateFileContexts(policy); err != nil {
		return nil, err
	}

	return policy, nil
}

// inferModuleName infers module name from policy structure
func (g *Generator) inferModuleName() string {
	// Try to extract from first policy subject
	if len(g.decoded.Policies) > 0 {
		subject := g.decoded.Policies[0].Subject
		// Clean and sanitize the subject name
		name := strings.ToLower(subject)
		name = strings.ReplaceAll(name, "_process", "")
		name = strings.ReplaceAll(name, "_t", "")
		return name
	}
	return "myapp"
}

// extractTypes extracts unique type names from subjects and objects and assigns attributes
func (g *Generator) extractTypes() map[string][]string {
	typeAttrs := make(map[string][]string)

	for _, policy := range g.decoded.Policies {
		// Add subject type - usually a domain type
		subjectType := g.typeMapper.SubjectToType(policy.Subject)
		if _, exists := typeAttrs[subjectType]; !exists {
			// Subject types are typically domain types
			typeAttrs[subjectType] = []string{"domain"}
		}

		// Add object type from path (use decoded object without condition)
		objPath := policy.Object
		if strings.HasPrefix(objPath, "/") {
			objectType := g.typeMapper.PathToType(objPath)
			if _, exists := typeAttrs[objectType]; !exists {
				// Determine attributes based on the class and path
				attrs := g.inferTypeAttributes(objPath, policy.Class)
				typeAttrs[objectType] = attrs
			}
		}
	}

	// Add types from transitions
	for _, trans := range g.decoded.Transitions {
		if _, exists := typeAttrs[trans.SourceType]; !exists {
			typeAttrs[trans.SourceType] = []string{"domain"}
		}
		if _, exists := typeAttrs[trans.TargetType]; !exists {
			// Target type in transition is typically an exec_type
			typeAttrs[trans.TargetType] = []string{"file_type", "exec_type"}
		}
		if _, exists := typeAttrs[trans.NewType]; !exists {
			typeAttrs[trans.NewType] = []string{"domain"}
		}
	}

	return typeAttrs
}

// inferTypeAttributes infers SELinux type attributes based on path and class
func (g *Generator) inferTypeAttributes(path string, class string) []string {
	// Common file type attribute for all file-related types
	attrs := []string{"file_type"}

	// Add specific attributes based on path patterns
	if strings.HasPrefix(path, "/usr/bin") || strings.HasPrefix(path, "/usr/sbin") ||
		strings.HasPrefix(path, "/bin") || strings.HasPrefix(path, "/sbin") {
		attrs = append(attrs, "exec_type")
	} else if strings.HasPrefix(path, "/var/log") {
		attrs = append(attrs, "logfile")
	} else if strings.HasPrefix(path, "/etc") {
		attrs = append(attrs, "configfile")
	}

	return attrs
}

// convertPolicies converts decoded PML policies to SELinux rules
func (g *Generator) convertPolicies(policy *models.SELinuxPolicy) error {
	for _, pmlPolicy := range g.decoded.Policies {
		sourceType := g.typeMapper.SubjectToType(pmlPolicy.Subject)

		// Determine target type and class based on object
		var targetType string
		class := pmlPolicy.Class // Use the decoded class

		// Handle special objects
		if pmlPolicy.Object == "self" {
			targetType = "self"
		} else if strings.HasPrefix(pmlPolicy.Object, "tcp:") || strings.HasPrefix(pmlPolicy.Object, "udp:") {
			// Network port binding - handle specially
			// Extract port number
			parts := strings.SplitN(pmlPolicy.Object, ":", 2)
			if len(parts) == 2 {
				// For port binding, we need to generate port type
				// For now, we'll use a generic approach
				targetType = "self"
				// The class should already be tcp_socket or udp_socket from decode
			}
		} else if strings.HasPrefix(pmlPolicy.Object, "/") {
			// File system path
			targetType = g.typeMapper.PathToType(pmlPolicy.Object)
		} else {
			// Other objects (treat as type name)
			targetType = g.typeMapper.SubjectToType(pmlPolicy.Object)
		}

		// Map action to permissions using the decoded class
		_, perms := g.actionMapper.MapAction(pmlPolicy.Action, class)

		if pmlPolicy.Effect == "allow" {
			rule := models.AllowRule{
				SourceType:  sourceType,
				TargetType:  targetType,
				Class:       class,
				Permissions: perms,
			}
			policy.Rules = append(policy.Rules, rule)
		} else if pmlPolicy.Effect == "deny" {
			// Deny rules not supported in simplified version - log warning
			// In production, you might want to use audit_deny or neverallow
			fmt.Printf("Warning: Deny rule skipped (not supported): %s -> %s:%s\n",
				sourceType, targetType, class)
		}
	}

	return nil
}

// convertTransitions converts decoded transitions to SELinux type_transition rules
func (g *Generator) convertTransitions(policy *models.SELinuxPolicy) error {
	for _, trans := range g.decoded.Transitions {
		// Ensure transition types are added to policy
		selinuxTrans := models.TypeTransition{
			SourceType: trans.SourceType,
			TargetType: trans.TargetType,
			Class:      trans.Class,
			NewType:    trans.NewType,
		}
		policy.Transitions = append(policy.Transitions, selinuxTrans)

		// Ensure all types are declared
		g.ensureType(policy, trans.SourceType)
		g.ensureType(policy, trans.TargetType)
		g.ensureType(policy, trans.NewType)

		// Generate domain transition helper rules if class is process
		if trans.Class == "process" {
			g.generateDomainTransitionRules(policy, trans.SourceType, trans.TargetType, trans.NewType)
		}
	}
	return nil
}

// generateDomainTransitionRules generates helper rules for domain transitions
// Adds the necessary rules for a process domain transition to work
func (g *Generator) generateDomainTransitionRules(policy *models.SELinuxPolicy, sourceType, execType, targetType string) {
	// Rule 1: Source domain can execute the target binary
	policy.Rules = append(policy.Rules, models.AllowRule{
		SourceType:  sourceType,
		TargetType:  execType,
		Class:       "file",
		Permissions: []string{"execute", "read", "open", "getattr"},
	})

	// Rule 2: Source domain can transition to target domain
	policy.Rules = append(policy.Rules, models.AllowRule{
		SourceType:  sourceType,
		TargetType:  targetType,
		Class:       "process",
		Permissions: []string{"transition"},
	})

	// Rule 3: Target domain entry point is the executable
	policy.Rules = append(policy.Rules, models.AllowRule{
		SourceType:  targetType,
		TargetType:  execType,
		Class:       "file",
		Permissions: []string{"entrypoint"},
	})

	// Mark executable type with exec_type attribute if not already present
	for i, typeDecl := range policy.Types {
		if typeDecl.TypeName == execType {
			if !containsAttribute(typeDecl.Attributes, "exec_type") {
				policy.Types[i].Attributes = append(policy.Types[i].Attributes, "exec_type")
			}
			break
		}
	}
}

// ensureType ensures a type is declared in the policy
func (g *Generator) ensureType(policy *models.SELinuxPolicy, typeName string) {
	for _, t := range policy.Types {
		if t.TypeName == typeName {
			return
		}
	}
	policy.Types = append(policy.Types, models.TypeDeclaration{
		TypeName: typeName,
	})
}

// actionToPermissions maps PML action to SELinux class and permissions
func (g *Generator) actionToPermissions(action string) (string, []string) {
	// Use the action mapper for consistent mapping
	class, permissions := g.actionMapper.MapAction(action, "")
	return class, permissions
}

// generateFileContexts generates file context entries
func (g *Generator) generateFileContexts(policy *models.SELinuxPolicy) error {
	seenPaths := make(map[string]bool)

	for _, pmlPolicy := range g.decoded.Policies {
		// Only generate contexts for file paths
		if !strings.HasPrefix(pmlPolicy.Object, "/") {
			continue
		}

		if seenPaths[pmlPolicy.Object] {
			continue
		}
		seenPaths[pmlPolicy.Object] = true

		// Generate recursive patterns for directories
		patterns := g.pathMapper.GenerateRecursivePatterns(pmlPolicy.Object)
		objectType := g.typeMapper.PathToType(pmlPolicy.Object)

		for _, pattern := range patterns {
			fc := models.FileContext{
				PathPattern: pattern.Pattern,
				FileType:    pattern.FileType, // -- or -d
				SELinuxType: objectType,
				Comment:     fmt.Sprintf("Generated from PML policy: %s", pmlPolicy.Object),
			}

			policy.FileContexts = append(policy.FileContexts, fc)
		}
	}

	return nil
}

// Helper function to check if attributes contain a specific attribute
func containsAttribute(attributes []string, attr string) bool {
	for _, a := range attributes {
		if a == attr {
			return true
		}
	}
	return false
}
