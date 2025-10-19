package compiler

import (
	"sort"

	"github.com/cici0602/pml-to-selinux/models"
)

// Optimizer handles optimization of SELinux policies
type Optimizer struct {
	policy *models.SELinuxPolicy
}

// NewOptimizer creates a new Optimizer instance
func NewOptimizer(policy *models.SELinuxPolicy) *Optimizer {
	return &Optimizer{
		policy: policy,
	}
}

// Optimize optimizes the policy by merging rules, removing duplicates, etc.
func (o *Optimizer) Optimize() error {
	// Merge allow rules with same source, target, and class
	o.mergeAllowRules()

	// Remove duplicate types
	o.deduplicateTypes()

	// Remove duplicate file contexts
	o.deduplicateFileContexts()

	// Deny rules removed in simplified version

	// Remove redundant rules (covered by more general rules)
	o.removeRedundantRules()

	// Remove unused types
	o.removeUnusedTypes()

	return nil
}

// mergeAllowRules merges allow rules with the same source, target, and class
func (o *Optimizer) mergeAllowRules() {
	if len(o.policy.Rules) == 0 {
		return
	}

	// Create a map to group rules
	ruleMap := make(map[string]*models.AllowRule)

	for _, rule := range o.policy.Rules {
		key := rule.SourceType + "|" + rule.TargetType + "|" + rule.Class

		if existing, ok := ruleMap[key]; ok {
			// Merge permissions
			existing.Permissions = append(existing.Permissions, rule.Permissions...)
			// Keep the first original object reference
		} else {
			// Create a copy of the rule
			ruleCopy := rule
			ruleMap[key] = &ruleCopy
		}
	}

	// Convert map back to slice
	merged := make([]models.AllowRule, 0, len(ruleMap))
	for _, rule := range ruleMap {
		// Deduplicate permissions
		rule.Permissions = uniqueStringSlice(rule.Permissions)
		// Sort permissions for consistent output
		sort.Strings(rule.Permissions)
		merged = append(merged, *rule)
	}

	// Sort merged rules for consistent output
	sort.Slice(merged, func(i, j int) bool {
		if merged[i].SourceType != merged[j].SourceType {
			return merged[i].SourceType < merged[j].SourceType
		}
		if merged[i].TargetType != merged[j].TargetType {
			return merged[i].TargetType < merged[j].TargetType
		}
		return merged[i].Class < merged[j].Class
	})

	o.policy.Rules = merged
}

// deduplicateTypes removes duplicate type declarations
func (o *Optimizer) deduplicateTypes() {
	if len(o.policy.Types) == 0 {
		return
	}

	typeMap := make(map[string]models.TypeDeclaration)

	for _, typeDecl := range o.policy.Types {
		if existing, ok := typeMap[typeDecl.TypeName]; ok {
			// Merge attributes
			existing.Attributes = append(existing.Attributes, typeDecl.Attributes...)
			existing.Attributes = uniqueStringSlice(existing.Attributes)
			sort.Strings(existing.Attributes)
			typeMap[typeDecl.TypeName] = existing
		} else {
			typeMap[typeDecl.TypeName] = typeDecl
		}
	}

	// Convert map back to slice
	deduplicated := make([]models.TypeDeclaration, 0, len(typeMap))
	for _, typeDecl := range typeMap {
		deduplicated = append(deduplicated, typeDecl)
	}

	// Sort types for consistent output
	sort.Slice(deduplicated, func(i, j int) bool {
		return deduplicated[i].TypeName < deduplicated[j].TypeName
	})

	o.policy.Types = deduplicated
}

// deduplicateFileContexts removes duplicate file context definitions
func (o *Optimizer) deduplicateFileContexts() {
	if len(o.policy.FileContexts) == 0 {
		return
	}

	contextMap := make(map[string]models.FileContext)

	for _, fc := range o.policy.FileContexts {
		key := fc.PathPattern + "|" + fc.FileType

		if _, ok := contextMap[key]; !ok {
			contextMap[key] = fc
		}
		// If duplicate, keep the first one
	}

	// Convert map back to slice
	deduplicated := make([]models.FileContext, 0, len(contextMap))
	for _, fc := range contextMap {
		deduplicated = append(deduplicated, fc)
	}

	// Sort file contexts for consistent output
	sort.Slice(deduplicated, func(i, j int) bool {
		return deduplicated[i].PathPattern < deduplicated[j].PathPattern
	})

	o.policy.FileContexts = deduplicated
}

// deduplicateDenyRules - Removed in simplified version
// Deny rules are not supported in MVP
func (o *Optimizer) deduplicateDenyRules() {
	// No-op: deny rules not supported
}

// uniqueStringSlice removes duplicates from a string slice
func uniqueStringSlice(slice []string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0, len(slice))

	for _, item := range slice {
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}

	return result
}

// GetStatistics returns optimization statistics
type OptimizationStats struct {
	OriginalRuleCount      int
	OptimizedRuleCount     int
	OriginalTypeCount      int
	OptimizedTypeCount     int
	OriginalContextCount   int
	OptimizedContextCount  int
	OriginalDenyRuleCount  int
	OptimizedDenyRuleCount int
}

// GetStatistics calculates optimization statistics
func (o *Optimizer) GetStatistics(originalPolicy *models.SELinuxPolicy) OptimizationStats {
	return OptimizationStats{
		OriginalRuleCount:      len(originalPolicy.Rules),
		OptimizedRuleCount:     len(o.policy.Rules),
		OriginalTypeCount:      len(originalPolicy.Types),
		OptimizedTypeCount:     len(o.policy.Types),
		OriginalContextCount:   len(originalPolicy.FileContexts),
		OptimizedContextCount:  len(o.policy.FileContexts),
		OriginalDenyRuleCount:  0, // Deny rules not supported in MVP
		OptimizedDenyRuleCount: 0, // Deny rules not supported in MVP
	}
}

// OptimizePolicy is a convenience function to optimize a policy
func OptimizePolicy(policy *models.SELinuxPolicy) error {
	optimizer := NewOptimizer(policy)
	return optimizer.Optimize()
}

// removeRedundantRules removes rules that are redundant or covered by more general rules
func (o *Optimizer) removeRedundantRules() {
	if len(o.policy.Rules) == 0 {
		return
	}

	// Build a map of rules for quick lookup
	ruleMap := make(map[string]models.AllowRule)
	for _, rule := range o.policy.Rules {
		key := rule.SourceType + "|" + rule.TargetType + "|" + rule.Class
		ruleMap[key] = rule
	}

	// Check for subsumption: rule A subsumes rule B if they have the same
	// source, target, and class, and A's permissions are a superset of B's
	nonRedundant := make([]models.AllowRule, 0)

	for _, rule := range o.policy.Rules {
		isRedundant := false

		for _, otherRule := range o.policy.Rules {
			if rule.SourceType == otherRule.SourceType &&
				rule.TargetType == otherRule.TargetType &&
				rule.Class == otherRule.Class &&
				len(otherRule.Permissions) > len(rule.Permissions) &&
				isSubset(rule.Permissions, otherRule.Permissions) {
				isRedundant = true
				break
			}
		}

		if !isRedundant {
			nonRedundant = append(nonRedundant, rule)
		}
	}

	o.policy.Rules = nonRedundant
}

// removeUnusedTypes removes type declarations that are not referenced in any rules
func (o *Optimizer) removeUnusedTypes() {
	if len(o.policy.Types) == 0 {
		return
	}

	// Collect all types used in rules, transitions, and file contexts
	usedTypes := make(map[string]bool)

	for _, rule := range o.policy.Rules {
		usedTypes[rule.SourceType] = true
		usedTypes[rule.TargetType] = true
	}

	// Deny rules removed in simplified version

	for _, trans := range o.policy.Transitions {
		usedTypes[trans.SourceType] = true
		usedTypes[trans.TargetType] = true
		usedTypes[trans.NewType] = true
	}

	// Keep only types that are used
	usedTypesList := make([]models.TypeDeclaration, 0)
	for _, typeDecl := range o.policy.Types {
		if usedTypes[typeDecl.TypeName] {
			usedTypesList = append(usedTypesList, typeDecl)
		}
	}

	o.policy.Types = usedTypesList
}

// isSubset checks if all elements of subset are in superset
func isSubset(subset, superset []string) bool {
	superMap := make(map[string]bool)
	for _, item := range superset {
		superMap[item] = true
	}

	for _, item := range subset {
		if !superMap[item] {
			return false
		}
	}

	return true
}

// AnalyzeComplexity analyzes the complexity of the policy
type ComplexityAnalysis struct {
	TotalRules          int
	TotalTypes          int
	TotalBooleans       int
	AverageRulesPerType float64
	MaxRulesPerType     int
	ComplexityScore     int // Simple heuristic: total_rules + total_types*2
}

// AnalyzeComplexity performs complexity analysis on the policy
func (o *Optimizer) AnalyzeComplexity() ComplexityAnalysis {
	// Count rules per type
	rulesPerType := make(map[string]int)
	for _, rule := range o.policy.Rules {
		rulesPerType[rule.SourceType]++
	}

	maxRules := 0
	totalRulesInTypes := 0
	for _, count := range rulesPerType {
		if count > maxRules {
			maxRules = count
		}
		totalRulesInTypes += count
	}

	avgRules := 0.0
	if len(rulesPerType) > 0 {
		avgRules = float64(totalRulesInTypes) / float64(len(rulesPerType))
	}

	return ComplexityAnalysis{
		TotalRules:          len(o.policy.Rules),
		TotalTypes:          len(o.policy.Types),
		AverageRulesPerType: avgRules,
		MaxRulesPerType:     maxRules,
		ComplexityScore:     len(o.policy.Rules) + len(o.policy.Types)*2,
	}
}
