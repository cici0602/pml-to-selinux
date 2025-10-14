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

	// Remove duplicate deny rules
	o.deduplicateDenyRules()

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

// deduplicateDenyRules removes duplicate deny rules
func (o *Optimizer) deduplicateDenyRules() {
	if len(o.policy.DenyRules) == 0 {
		return
	}

	// Create a map to group deny rules
	ruleMap := make(map[string]*models.DenyRule)

	for _, rule := range o.policy.DenyRules {
		key := rule.SourceType + "|" + rule.TargetType + "|" + rule.Class

		if existing, ok := ruleMap[key]; ok {
			// Merge permissions
			existing.Permissions = append(existing.Permissions, rule.Permissions...)
		} else {
			// Create a copy of the rule
			ruleCopy := rule
			ruleMap[key] = &ruleCopy
		}
	}

	// Convert map back to slice
	deduplicated := make([]models.DenyRule, 0, len(ruleMap))
	for _, rule := range ruleMap {
		// Deduplicate permissions
		rule.Permissions = uniqueStringSlice(rule.Permissions)
		// Sort permissions for consistent output
		sort.Strings(rule.Permissions)
		deduplicated = append(deduplicated, *rule)
	}

	// Sort deny rules for consistent output
	sort.Slice(deduplicated, func(i, j int) bool {
		if deduplicated[i].SourceType != deduplicated[j].SourceType {
			return deduplicated[i].SourceType < deduplicated[j].SourceType
		}
		if deduplicated[i].TargetType != deduplicated[j].TargetType {
			return deduplicated[i].TargetType < deduplicated[j].TargetType
		}
		return deduplicated[i].Class < deduplicated[j].Class
	})

	o.policy.DenyRules = deduplicated
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
		OriginalDenyRuleCount:  len(originalPolicy.DenyRules),
		OptimizedDenyRuleCount: len(o.policy.DenyRules),
	}
}

// OptimizePolicy is a convenience function to optimize a policy
func OptimizePolicy(policy *models.SELinuxPolicy) error {
	optimizer := NewOptimizer(policy)
	return optimizer.Optimize()
}
