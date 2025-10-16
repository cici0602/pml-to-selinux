package compiler

import (
	"fmt"
	"strings"

	"github.com/cici0602/pml-to-selinux/models"
)

// Differ compares two SELinux policies and reports differences
type Differ struct {
	policy1 *models.SELinuxPolicy
	policy2 *models.SELinuxPolicy
}

// NewDiffer creates a new Differ instance
func NewDiffer(policy1, policy2 *models.SELinuxPolicy) *Differ {
	return &Differ{
		policy1: policy1,
		policy2: policy2,
	}
}

// DiffResult contains the differences between two policies
type DiffResult struct {
	TypesAdded      []string
	TypesRemoved    []string
	RulesAdded      []string
	RulesRemoved    []string
	RulesModified   []string
	ContextsAdded   []string
	ContextsRemoved []string
}

// Diff compares two policies and returns the differences
func (d *Differ) Diff() *DiffResult {
	result := &DiffResult{
		TypesAdded:      make([]string, 0),
		TypesRemoved:    make([]string, 0),
		RulesAdded:      make([]string, 0),
		RulesRemoved:    make([]string, 0),
		RulesModified:   make([]string, 0),
		ContextsAdded:   make([]string, 0),
		ContextsRemoved: make([]string, 0),
	}

	// Compare types
	d.compareTypes(result)

	// Compare rules
	d.compareRules(result)

	// Compare file contexts
	d.compareFileContexts(result)

	return result
}

// compareTypes compares type declarations
func (d *Differ) compareTypes(result *DiffResult) {
	types1 := make(map[string]bool)
	types2 := make(map[string]bool)

	for _, t := range d.policy1.Types {
		types1[t.TypeName] = true
	}

	for _, t := range d.policy2.Types {
		types2[t.TypeName] = true
	}

	// Find added types
	for typeName := range types2 {
		if !types1[typeName] {
			result.TypesAdded = append(result.TypesAdded, typeName)
		}
	}

	// Find removed types
	for typeName := range types1 {
		if !types2[typeName] {
			result.TypesRemoved = append(result.TypesRemoved, typeName)
		}
	}
}

// compareRules compares allow rules
func (d *Differ) compareRules(result *DiffResult) {
	rules1 := make(map[string]models.AllowRule)
	rules2 := make(map[string]models.AllowRule)

	for _, r := range d.policy1.Rules {
		key := ruleKey(r)
		rules1[key] = r
	}

	for _, r := range d.policy2.Rules {
		key := ruleKey(r)
		rules2[key] = r
	}

	// Find added rules
	for key, rule := range rules2 {
		if _, exists := rules1[key]; !exists {
			result.RulesAdded = append(result.RulesAdded, formatRule(rule))
		}
	}

	// Find removed rules
	for key, rule := range rules1 {
		if _, exists := rules2[key]; !exists {
			result.RulesRemoved = append(result.RulesRemoved, formatRule(rule))
		}
	}

	// Find modified rules (same source/target/class but different permissions)
	for key1, rule1 := range rules1 {
		for key2, rule2 := range rules2 {
			if rule1.SourceType == rule2.SourceType &&
				rule1.TargetType == rule2.TargetType &&
				rule1.Class == rule2.Class &&
				!permissionsEqual(rule1.Permissions, rule2.Permissions) {
				result.RulesModified = append(result.RulesModified,
					fmt.Sprintf("%s -> %s", formatRule(rule1), formatRule(rule2)))
				delete(rules1, key1)
				delete(rules2, key2)
			}
		}
	}
}

// compareFileContexts compares file contexts
func (d *Differ) compareFileContexts(result *DiffResult) {
	contexts1 := make(map[string]bool)
	contexts2 := make(map[string]bool)

	for _, fc := range d.policy1.FileContexts {
		key := fmt.Sprintf("%s -> %s", fc.PathPattern, fc.Context)
		contexts1[key] = true
	}

	for _, fc := range d.policy2.FileContexts {
		key := fmt.Sprintf("%s -> %s", fc.PathPattern, fc.Context)
		contexts2[key] = true
	}

	// Find added contexts
	for ctx := range contexts2 {
		if !contexts1[ctx] {
			result.ContextsAdded = append(result.ContextsAdded, ctx)
		}
	}

	// Find removed contexts
	for ctx := range contexts1 {
		if !contexts2[ctx] {
			result.ContextsRemoved = append(result.ContextsRemoved, ctx)
		}
	}
}

// Helper functions

func ruleKey(rule models.AllowRule) string {
	perms := strings.Join(rule.Permissions, ",")
	return fmt.Sprintf("%s:%s:%s:%s", rule.SourceType, rule.TargetType, rule.Class, perms)
}

func formatRule(rule models.AllowRule) string {
	perms := strings.Join(rule.Permissions, ", ")
	return fmt.Sprintf("allow %s %s:%s { %s }", rule.SourceType, rule.TargetType, rule.Class, perms)
}

func permissionsEqual(p1, p2 []string) bool {
	if len(p1) != len(p2) {
		return false
	}
	m := make(map[string]bool)
	for _, p := range p1 {
		m[p] = true
	}
	for _, p := range p2 {
		if !m[p] {
			return false
		}
	}
	return true
}

// FormatDiff formats the diff result as a human-readable string
func FormatDiff(result *DiffResult) string {
	var builder strings.Builder

	if len(result.TypesAdded) > 0 {
		builder.WriteString("Types Added:\n")
		for _, t := range result.TypesAdded {
			builder.WriteString(fmt.Sprintf("  + %s\n", t))
		}
		builder.WriteString("\n")
	}

	if len(result.TypesRemoved) > 0 {
		builder.WriteString("Types Removed:\n")
		for _, t := range result.TypesRemoved {
			builder.WriteString(fmt.Sprintf("  - %s\n", t))
		}
		builder.WriteString("\n")
	}

	if len(result.RulesAdded) > 0 {
		builder.WriteString("Rules Added:\n")
		for _, r := range result.RulesAdded {
			builder.WriteString(fmt.Sprintf("  + %s\n", r))
		}
		builder.WriteString("\n")
	}

	if len(result.RulesRemoved) > 0 {
		builder.WriteString("Rules Removed:\n")
		for _, r := range result.RulesRemoved {
			builder.WriteString(fmt.Sprintf("  - %s\n", r))
		}
		builder.WriteString("\n")
	}

	if len(result.RulesModified) > 0 {
		builder.WriteString("Rules Modified:\n")
		for _, r := range result.RulesModified {
			builder.WriteString(fmt.Sprintf("  ~ %s\n", r))
		}
		builder.WriteString("\n")
	}

	if len(result.ContextsAdded) > 0 {
		builder.WriteString("File Contexts Added:\n")
		for _, c := range result.ContextsAdded {
			builder.WriteString(fmt.Sprintf("  + %s\n", c))
		}
		builder.WriteString("\n")
	}

	if len(result.ContextsRemoved) > 0 {
		builder.WriteString("File Contexts Removed:\n")
		for _, c := range result.ContextsRemoved {
			builder.WriteString(fmt.Sprintf("  - %s\n", c))
		}
		builder.WriteString("\n")
	}

	if builder.Len() == 0 {
		return "No differences found.\n"
	}

	return builder.String()
}
