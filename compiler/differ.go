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
		key := fmt.Sprintf("%s -> %s", fc.PathPattern, fc.SELinuxType)
		contexts1[key] = true
	}

	for _, fc := range d.policy2.FileContexts {
		key := fmt.Sprintf("%s -> %s", fc.PathPattern, fc.SELinuxType)
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

// ConflictAnalysis contains detected policy conflicts
type ConflictAnalysis struct {
	AllowDenyConflicts   []string // Rules where same access is both allowed and denied
	OverlappingRules     []string // Rules that may overlap in unintended ways
	TypeMismatches       []string // Type usage inconsistencies
	MissingDependencies  []string // Types used but not declared
	CircularDependencies []string // Circular dependencies in type transitions
}

// DetectConflicts analyzes a policy for potential conflicts
func DetectConflicts(policy *models.SELinuxPolicy) *ConflictAnalysis {
	analysis := &ConflictAnalysis{
		AllowDenyConflicts:   make([]string, 0), // Not used in simplified version
		OverlappingRules:     make([]string, 0),
		TypeMismatches:       make([]string, 0),
		MissingDependencies:  make([]string, 0),
		CircularDependencies: make([]string, 0),
	}

	// Check for overlapping rules
	analysis.OverlappingRules = detectOverlappingRules(policy)

	// Check for missing type declarations
	analysis.MissingDependencies = detectMissingTypes(policy)

	// Check for circular dependencies in transitions
	analysis.CircularDependencies = detectCircularDependencies(policy)

	return analysis
}

// detectAllowDenyConflicts - Removed in simplified version (no deny rules)
// Deny rules are not supported in the MVP version
func detectAllowDenyConflicts(policy *models.SELinuxPolicy) []string {
	return make([]string, 0)
}

// detectOverlappingRules finds rules that may have unintended overlaps
func detectOverlappingRules(policy *models.SELinuxPolicy) []string {
	overlaps := make([]string, 0)

	// Group rules by source type
	rulesBySource := make(map[string][]models.AllowRule)
	for _, rule := range policy.Rules {
		rulesBySource[rule.SourceType] = append(rulesBySource[rule.SourceType], rule)
	}

	// Check for rules with identical source, target, and class
	for source, rules := range rulesBySource {
		seen := make(map[string]bool)
		for _, rule := range rules {
			key := fmt.Sprintf("%s|%s", rule.TargetType, rule.Class)
			if seen[key] {
				overlap := fmt.Sprintf("OVERLAP: Multiple rules for %s accessing %s:%s",
					source, rule.TargetType, rule.Class)
				overlaps = append(overlaps, overlap)
			}
			seen[key] = true
		}
	}

	return overlaps
}

// detectMissingTypes finds types used in rules but not declared
func detectMissingTypes(policy *models.SELinuxPolicy) []string {
	missing := make([]string, 0)

	// Build set of declared types
	declaredTypes := make(map[string]bool)
	for _, typeDecl := range policy.Types {
		declaredTypes[typeDecl.TypeName] = true
	}

	// Check types in allow rules
	usedTypes := make(map[string]bool)
	for _, rule := range policy.Rules {
		usedTypes[rule.SourceType] = true
		usedTypes[rule.TargetType] = true
	}

	// Deny rules removed in simplified version

	// Check types in transitions
	for _, trans := range policy.Transitions {
		usedTypes[trans.SourceType] = true
		usedTypes[trans.TargetType] = true
		usedTypes[trans.NewType] = true
	}

	// Find missing types
	for typeName := range usedTypes {
		if !declaredTypes[typeName] {
			missing = append(missing, fmt.Sprintf("Type '%s' is used but not declared", typeName))
		}
	}

	return missing
}

// detectCircularDependencies finds circular dependencies in type transitions
func detectCircularDependencies(policy *models.SELinuxPolicy) []string {
	circular := make([]string, 0)

	// Build transition graph
	graph := make(map[string][]string) // source -> targets

	for _, trans := range policy.Transitions {
		key := fmt.Sprintf("%s:%s", trans.SourceType, trans.TargetType)
		graph[key] = append(graph[key], trans.NewType)
	}

	// Check for cycles (simplified DFS)
	visited := make(map[string]bool)
	recStack := make(map[string]bool)

	var detectCycle func(node string) bool
	detectCycle = func(node string) bool {
		visited[node] = true
		recStack[node] = true

		for _, neighbor := range graph[node] {
			neighborKey := neighbor
			for k := range graph {
				if strings.HasPrefix(k, neighborKey+":") {
					if !visited[k] {
						if detectCycle(k) {
							return true
						}
					} else if recStack[k] {
						circular = append(circular, fmt.Sprintf("Circular dependency detected: %s -> %s", node, k))
						return true
					}
				}
			}
		}

		recStack[node] = false
		return false
	}

	for node := range graph {
		if !visited[node] {
			detectCycle(node)
		}
	}

	return circular
}

// FormatConflictAnalysis formats conflict analysis as a human-readable string
func FormatConflictAnalysis(analysis *ConflictAnalysis) string {
	var builder strings.Builder

	hasConflicts := false

	if len(analysis.AllowDenyConflicts) > 0 {
		hasConflicts = true
		builder.WriteString("Allow/Deny Conflicts:\n")
		for _, conflict := range analysis.AllowDenyConflicts {
			builder.WriteString(fmt.Sprintf("  ! %s\n", conflict))
		}
		builder.WriteString("\n")
	}

	if len(analysis.OverlappingRules) > 0 {
		hasConflicts = true
		builder.WriteString("Overlapping Rules:\n")
		for _, overlap := range analysis.OverlappingRules {
			builder.WriteString(fmt.Sprintf("  ! %s\n", overlap))
		}
		builder.WriteString("\n")
	}

	if len(analysis.MissingDependencies) > 0 {
		hasConflicts = true
		builder.WriteString("Missing Type Declarations:\n")
		for _, missing := range analysis.MissingDependencies {
			builder.WriteString(fmt.Sprintf("  ! %s\n", missing))
		}
		builder.WriteString("\n")
	}

	if len(analysis.CircularDependencies) > 0 {
		hasConflicts = true
		builder.WriteString("Circular Dependencies:\n")
		for _, circular := range analysis.CircularDependencies {
			builder.WriteString(fmt.Sprintf("  ! %s\n", circular))
		}
		builder.WriteString("\n")
	}

	if !hasConflicts {
		return "No conflicts detected.\n"
	}

	return builder.String()
}
