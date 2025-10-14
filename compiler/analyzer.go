package compiler

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/cici0602/pml-to-selinux/models"
)

// Analyzer performs semantic analysis on parsed PML
type Analyzer struct {
	pml    *models.ParsedPML
	errors []error
	stats  *AnalysisStats
}

// AnalysisStats contains statistics about the analyzed policy
type AnalysisStats struct {
	TotalPolicies  int
	AllowRules     int
	DenyRules      int
	UniqueSubjects int
	UniqueObjects  int
	UniqueActions  int
	Conflicts      int
	RoleRelations  int
	SubjectTypes   map[string]int // Count of rules per subject
	ObjectPatterns map[string]int // Count of rules per object pattern
	ActionTypes    map[string]int // Count of rules per action
}

// ConflictInfo represents a policy conflict
type ConflictInfo struct {
	AllowRule models.Policy
	DenyRule  models.Policy
	Reason    string
}

// NewAnalyzer creates a new analyzer instance
func NewAnalyzer(pml *models.ParsedPML) *Analyzer {
	return &Analyzer{
		pml:    pml,
		errors: make([]error, 0),
		stats: &AnalysisStats{
			SubjectTypes:   make(map[string]int),
			ObjectPatterns: make(map[string]int),
			ActionTypes:    make(map[string]int),
		},
	}
}

// Analyze performs comprehensive analysis on the PML
func (a *Analyzer) Analyze() error {
	// Validate model completeness
	if err := a.validateModel(); err != nil {
		return err
	}

	// Check policy rules validity
	if err := a.validatePolicies(); err != nil {
		return err
	}

	// Detect policy conflicts
	conflicts := a.detectConflicts()
	if len(conflicts) > 0 {
		a.stats.Conflicts = len(conflicts)
		// Log conflicts as warnings, not errors
		for _, conflict := range conflicts {
			a.addWarning(fmt.Sprintf("Policy conflict detected: %s", conflict.Reason))
		}
	}

	// Generate statistics
	a.generateStats()

	return nil
}

// validateModel checks if the model has all required sections
func (a *Analyzer) validateModel() error {
	model := a.pml.Model

	// Check request_definition
	if len(model.RequestDefinition) == 0 {
		return fmt.Errorf("model validation failed: request_definition is missing")
	}

	// Check if 'r' is defined in request_definition
	rDef, ok := model.RequestDefinition["r"]
	if !ok {
		return fmt.Errorf("model validation failed: 'r' is not defined in request_definition")
	}
	if len(rDef) == 0 {
		return fmt.Errorf("model validation failed: request_definition 'r' is empty")
	}

	// Check policy_definition
	if len(model.PolicyDefinition) == 0 {
		return fmt.Errorf("model validation failed: policy_definition is missing")
	}

	// Check if 'p' is defined in policy_definition
	pDef, ok := model.PolicyDefinition["p"]
	if !ok {
		return fmt.Errorf("model validation failed: 'p' is not defined in policy_definition")
	}
	if len(pDef) == 0 {
		return fmt.Errorf("model validation failed: policy_definition 'p' is empty")
	}

	// Check matchers
	if model.Matchers == "" {
		return fmt.Errorf("model validation failed: matchers section is missing")
	}

	// Check policy_effect
	if model.Effect == "" {
		return fmt.Errorf("model validation failed: policy_effect section is missing")
	}

	return nil
}

// validatePolicies checks if all policy rules are valid
func (a *Analyzer) validatePolicies() error {
	validEffects := map[string]bool{"allow": true, "deny": true}

	for i, policy := range a.pml.Policies {
		// Check if subject is not empty
		if policy.Subject == "" {
			return fmt.Errorf("policy rule %d: subject cannot be empty", i+1)
		}

		// Check if object is not empty
		if policy.Object == "" {
			return fmt.Errorf("policy rule %d: object cannot be empty", i+1)
		}

		// Check if action is not empty
		if policy.Action == "" {
			return fmt.Errorf("policy rule %d: action cannot be empty", i+1)
		}

		// Check if class is not empty
		if policy.Class == "" {
			return fmt.Errorf("policy rule %d: class cannot be empty", i+1)
		}

		// Check if effect is valid
		if !validEffects[policy.Effect] {
			return fmt.Errorf("policy rule %d: invalid effect '%s', must be 'allow' or 'deny'", i+1, policy.Effect)
		}

		// Validate path patterns
		if err := a.validatePathPattern(policy.Object); err != nil {
			return fmt.Errorf("policy rule %d: invalid object pattern '%s': %w", i+1, policy.Object, err)
		}
	}

	return nil
}

// validatePathPattern validates if a path pattern is valid
func (a *Analyzer) validatePathPattern(pattern string) error {
	// Check if pattern starts with /
	if !strings.HasPrefix(pattern, "/") {
		// Allow special patterns like tcp_socket
		if !strings.Contains(pattern, "_") {
			return fmt.Errorf("path pattern must start with '/' or be a valid object type")
		}
	}

	// Check for invalid characters
	// Allow: alphanumeric, /, *, ., -, _
	for _, ch := range pattern {
		if !isValidPathChar(ch) {
			return fmt.Errorf("invalid character '%c' in path pattern", ch)
		}
	}

	return nil
}

// isValidPathChar checks if a character is valid in a path pattern
func isValidPathChar(ch rune) bool {
	return (ch >= 'a' && ch <= 'z') ||
		(ch >= 'A' && ch <= 'Z') ||
		(ch >= '0' && ch <= '9') ||
		ch == '/' || ch == '*' || ch == '.' || ch == '-' || ch == '_'
}

// detectConflicts finds conflicting allow and deny rules
func (a *Analyzer) detectConflicts() []ConflictInfo {
	var conflicts []ConflictInfo

	// Group policies by subject for efficient comparison
	allowRules := make(map[string][]models.Policy)
	denyRules := make(map[string][]models.Policy)

	for _, policy := range a.pml.Policies {
		key := policy.Subject
		if policy.Effect == "allow" {
			allowRules[key] = append(allowRules[key], policy)
		} else if policy.Effect == "deny" {
			denyRules[key] = append(denyRules[key], policy)
		}
	}

	// Check for conflicts
	for subject, allows := range allowRules {
		denies, hasDeny := denyRules[subject]
		if !hasDeny {
			continue
		}

		for _, allowRule := range allows {
			for _, denyRule := range denies {
				if a.rulesConflict(allowRule, denyRule) {
					conflicts = append(conflicts, ConflictInfo{
						AllowRule: allowRule,
						DenyRule:  denyRule,
						Reason: fmt.Sprintf("Allow and deny rules conflict for subject '%s', object '%s', action '%s', class '%s'",
							subject, allowRule.Object, allowRule.Action, allowRule.Class),
					})
				}
			}
		}
	}

	return conflicts
}

// rulesConflict checks if two rules conflict
func (a *Analyzer) rulesConflict(allow, deny models.Policy) bool {
	// Rules conflict if they have the same subject, overlapping objects, same action, and same class
	if allow.Subject != deny.Subject {
		return false
	}
	if allow.Action != deny.Action {
		return false
	}
	if allow.Class != deny.Class {
		return false
	}

	// Check if objects overlap
	return a.pathsOverlap(allow.Object, deny.Object)
}

// pathsOverlap checks if two path patterns overlap
func (a *Analyzer) pathsOverlap(path1, path2 string) bool {
	// Simple overlap check: exact match or wildcard match
	if path1 == path2 {
		return true
	}

	// Check if one path is a wildcard version of the other
	base1 := filepath.Dir(path1)
	base2 := filepath.Dir(path2)

	if strings.HasSuffix(path1, "*") {
		if strings.HasPrefix(path2, strings.TrimSuffix(path1, "*")) {
			return true
		}
	}

	if strings.HasSuffix(path2, "*") {
		if strings.HasPrefix(path1, strings.TrimSuffix(path2, "*")) {
			return true
		}
	}

	// Check if paths share the same base directory
	if base1 == base2 && (strings.Contains(path1, "*") || strings.Contains(path2, "*")) {
		return true
	}

	return false
}

// generateStats generates statistics about the policies
func (a *Analyzer) generateStats() {
	stats := a.stats

	stats.TotalPolicies = len(a.pml.Policies)
	stats.RoleRelations = len(a.pml.Roles)

	uniqueSubjects := make(map[string]bool)
	uniqueObjects := make(map[string]bool)
	uniqueActions := make(map[string]bool)

	for _, policy := range a.pml.Policies {
		// Count allow and deny rules
		if policy.Effect == "allow" {
			stats.AllowRules++
		} else if policy.Effect == "deny" {
			stats.DenyRules++
		}

		// Track unique values
		uniqueSubjects[policy.Subject] = true
		uniqueObjects[policy.Object] = true
		uniqueActions[policy.Action] = true

		// Count per type
		stats.SubjectTypes[policy.Subject]++
		stats.ObjectPatterns[policy.Object]++
		stats.ActionTypes[policy.Action]++
	}

	stats.UniqueSubjects = len(uniqueSubjects)
	stats.UniqueObjects = len(uniqueObjects)
	stats.UniqueActions = len(uniqueActions)
}

// GetStats returns the analysis statistics
func (a *Analyzer) GetStats() *AnalysisStats {
	return a.stats
}

// addWarning adds a warning message (non-fatal)
func (a *Analyzer) addWarning(msg string) {
	// For now, just collect as errors, but mark them as warnings
	// In the future, we could have separate warning tracking
	fmt.Printf("WARNING: %s\n", msg)
}

// GetErrors returns all errors encountered during analysis
func (a *Analyzer) GetErrors() []error {
	return a.errors
}
