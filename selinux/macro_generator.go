package selinux

import (
	"fmt"
	"sort"
	"strings"

	"github.com/cici0602/pml-to-selinux/models"
)

// MacroGenerator handles generation of SELinux require statements
// Simplified version - no complex macros, just basic require blocks
type MacroGenerator struct {
	policy *models.SELinuxPolicy
}

// NewMacroGenerator creates a new MacroGenerator instance
func NewMacroGenerator(policy *models.SELinuxPolicy) *MacroGenerator {
	return &MacroGenerator{
		policy: policy,
	}
}

// GenerateRequireBlock generates a require block with all needed types, classes, and permissions
func (g *MacroGenerator) GenerateRequireBlock() string {
	var builder strings.Builder

	// Collect all types, classes, and permissions used
	types := make(map[string]bool)
	classes := make(map[string]map[string]bool) // class -> permissions

	// Extract from allow rules
	for _, rule := range g.policy.Rules {
		types[rule.SourceType] = true
		types[rule.TargetType] = true

		if classes[rule.Class] == nil {
			classes[rule.Class] = make(map[string]bool)
		}
		for _, perm := range rule.Permissions {
			classes[rule.Class][perm] = true
		}
	}

	// Extract from capabilities
	for _, cap := range g.policy.Capabilities {
		types[cap.SourceType] = true
		if classes["capability"] == nil {
			classes["capability"] = make(map[string]bool)
		}
		classes["capability"][cap.Capability] = true
	}

	// Extract from transitions
	for _, trans := range g.policy.Transitions {
		types[trans.SourceType] = true
		types[trans.TargetType] = true
		types[trans.NewType] = true
	}

	// Remove declared types (they don't need to be in require)
	declaredTypes := make(map[string]bool)
	for _, typeDecl := range g.policy.Types {
		declaredTypes[typeDecl.TypeName] = true
	}

	// Start require block
	builder.WriteString("require {\n")

	// Generate type statements
	externalTypes := make([]string, 0)
	for typeName := range types {
		if !declaredTypes[typeName] && typeName != "self" {
			externalTypes = append(externalTypes, typeName)
		}
	}
	sort.Strings(externalTypes)

	if len(externalTypes) > 0 {
		builder.WriteString("\ttype ")
		builder.WriteString(strings.Join(externalTypes, ", "))
		builder.WriteString(";\n")
	}

	// Generate class statements
	sortedClasses := make([]string, 0, len(classes))
	for class := range classes {
		sortedClasses = append(sortedClasses, class)
	}
	sort.Strings(sortedClasses)

	for _, class := range sortedClasses {
		perms := make([]string, 0, len(classes[class]))
		for perm := range classes[class] {
			perms = append(perms, perm)
		}
		sort.Strings(perms)

		builder.WriteString(fmt.Sprintf("\tclass %s { %s };\n",
			class, strings.Join(perms, " ")))
	}

	builder.WriteString("}\n")

	return builder.String()
}

// GenerateCommonMacros generates commonly used macros (simplified)
// For production use, reference standard refpolicy macros instead
func (g *MacroGenerator) GenerateCommonMacros() string {
	var builder strings.Builder

	builder.WriteString("# Common macro shortcuts (optional)\n")
	builder.WriteString("# In production, use standard refpolicy macros instead\n\n")

	// Only generate if there are file/dir rules
	hasFileRules := false
	for _, rule := range g.policy.Rules {
		if rule.Class == "file" || rule.Class == "dir" {
			hasFileRules = true
			break
		}
	}

	if hasFileRules {
		builder.WriteString("# Macro for basic file read access\n")
		builder.WriteString("# files_read_file(domain, file_type)\n")
		builder.WriteString("# Expands to: allow domain file_type:file { read open getattr };\n\n")
	}

	return builder.String()
}

// InferRequiredAttributes returns common attributes that should be added
func (g *MacroGenerator) InferRequiredAttributes() []string {
	attributes := make(map[string]bool)

	// Check what attributes we might need
	for _, rule := range g.policy.Rules {
		if strings.HasSuffix(rule.SourceType, "_t") {
			attributes["domain"] = true
		}
		if strings.HasSuffix(rule.TargetType, "_exec_t") {
			attributes["exec_type"] = true
			attributes["file_type"] = true
		}
		if rule.Class == "file" || rule.Class == "dir" {
			attributes["file_type"] = true
		}
	}

	result := make([]string, 0, len(attributes))
	for attr := range attributes {
		result = append(result, attr)
	}
	sort.Strings(result)

	return result
}
